package main

import (
	"context"
	"database/sql"
	"encoding/json"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
	"html/template"
	"log"
	"net/http"
	"time"
)

var (
	db                 *sql.DB
	googleOauth2Config = oauth2.Config{
		ClientID:     "375644221715-ofs1oqr56f693rhggu85743pvs425l39.apps.googleusercontent.com",
		ClientSecret: "yourclientsecret",
		//RedirectURL:  "https://zxcunit.ru/auth/google/callback",
		RedirectURL: "https://cd4b-23-95-170-243.ngrok-free.app/auth/google/callback",
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.profile",
			"https://www.googleapis.com/auth/userinfo.email",
		},
		Endpoint: google.Endpoint,
	}

	githubOauth2Config = oauth2.Config{
		ClientID:     "Ov23liS4yVY0QBEXa5tk",
		ClientSecret: "yourclientsecret",
		RedirectURL:  "https://zxcunit.ru/auth/github/callback",
		Scopes:       []string{"user"},
		Endpoint:     github.Endpoint,
	}

	oauth2StateString = "randomstate"
)

func init() {
	var err error
	db, err = sql.Open("sqlite3", "./users.db")
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			email TEXT NOT NULL,
			provider TEXT NOT NULL
		);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_email_and_provider ON users (email, provider);
	`)
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS comments (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT NOT NULL,
		comment TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_created_at ON comments(created_at);
	`)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/auth/google", handleGoogleLogin)
	http.HandleFunc("/auth/google/callback", handleGoogleCallback)
	http.HandleFunc("/auth/github", handleGithubLogin)
	http.HandleFunc("/auth/github/callback", handleGithubCallback)
	http.HandleFunc("/loadComments", loadMoreComments)
	http.HandleFunc("/submitComment", handleCommentSubmission)

	http.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.Dir("template/assets"))))
	//
	//server := &http.Server{
	//	Addr: ":80",
	//	TLSConfig: &tls.Config{
	//		InsecureSkipVerify: false,
	//		MinVersion:         tls.VersionTLS12,
	//	},
	//}

	log.Println("Сервер запущен на https://localhost:80")
	log.Fatal(http.ListenAndServe(":8080", nil))
	//log.Fatal(server.ListenAndServeTLS("cert.pem", "key.pem"))
}

func setCookies(w http.ResponseWriter, email, provider string) {
	var expires = time.Now().Add(24 * time.Hour)
	http.SetCookie(w, &http.Cookie{
		Name:    "email",
		Value:   email,
		Expires: expires,
		Path:    "/",
	})

	http.SetCookie(w, &http.Cookie{
		Name:    "provider",
		Value:   provider,
		Expires: expires,
		Path:    "/",
	})
}

func homeHandler(w http.ResponseWriter, r *http.Request) {

	tmpl, err := template.ParseFiles("template/index.html")
	if err != nil {
		http.Error(w, "Ошибка загрузки шаблона: "+err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)

}

func loadMoreComments(w http.ResponseWriter, r *http.Request) {
	offset := r.URL.Query().Get("offset")
	if offset == "" {
		offset = "0"
	}

	rows, err := db.Query("SELECT email, comment, created_at FROM comments ORDER BY created_at DESC LIMIT 10 OFFSET ?", offset)
	if err != nil {
		http.Error(w, "Ошибка загрузки комментариев: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var comments []struct {
		Email     string `json:"email"`
		Comment   string `json:"comment"`
		CreatedAt string `json:"created_at"`
	}

	for rows.Next() {
		var c struct {
			Email     string `json:"email"`
			Comment   string `json:"comment"`
			CreatedAt string `json:"created_at"`
		}
		if err := rows.Scan(&c.Email, &c.Comment, &c.CreatedAt); err != nil {
			http.Error(w, "Ошибка получения комментариев: "+err.Error(), http.StatusInternalServerError)
			return
		}
		comments = append(comments, c)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(comments)
}

func handleCommentSubmission(w http.ResponseWriter, r *http.Request) {
	emailCookie, err1 := r.Cookie("email")
	providerCookie, err2 := r.Cookie("provider")

	if err1 != nil || err2 != nil || emailCookie.Value == "" || providerCookie.Value == "" {
		http.Redirect(w, r, "/auth/google", http.StatusFound)
		return
	}

	r.ParseForm()
	comment := r.FormValue("comment")

	if comment == "" {
		http.Error(w, "Комментарий не может быть пустым", http.StatusBadRequest)
		return
	}

	_, err := db.Exec("INSERT INTO comments (email, comment) VALUES (?, ?)",
		emailCookie.Value, comment)
	if err != nil {
		http.Error(w, "Ошибка при добавлении комментария"+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func handleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	url := googleOauth2Config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func handleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Нет кода авторизации", http.StatusBadRequest)
		return
	}

	token, err := googleOauth2Config.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, "Ошибка обмена токена: "+err.Error(), http.StatusInternalServerError)
		return
	}

	client := googleOauth2Config.Client(context.Background(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		http.Error(w, "Ошибка получения данных о пользователе: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var userInfo = struct {
		Email string `json:"email"`
	}{}

	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		http.Error(w, "Ошибка обработки данных", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("INSERT OR REPLACE INTO users (email, provider) VALUES (?, ?)",
		userInfo.Email, "google")
	if err != nil {
		http.Error(w, "Ошибка сохранения пользователя: "+err.Error(), http.StatusInternalServerError)
		return
	}

	setCookies(w, userInfo.Email, "google")

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func handleGithubLogin(w http.ResponseWriter, r *http.Request) {
	url := githubOauth2Config.AuthCodeURL(oauth2StateString, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusFound)
}

func handleGithubCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	if state != oauth2StateString {
		http.Error(w, "State mismatch", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Code not found", http.StatusBadRequest)
		return
	}

	token, err := githubOauth2Config.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "Unable to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	client := githubOauth2Config.Client(r.Context(), token)
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		http.Error(w, "Unable to get user info: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	userInfo := struct {
		Email string `json:"email"`
	}{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		http.Error(w, "Unable to decode user info: "+err.Error(), http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("INSERT OR REPLACE INTO users (email,  provider) VALUES (?, ?)",
		userInfo.Email, "github")
	if err != nil {
		http.Error(w, "Ошибка сохранения пользователя: "+err.Error(), http.StatusInternalServerError)
		return
	}

	setCookies(w, userInfo.Email, "github")

	http.Redirect(w, r, "/", http.StatusSeeOther)
}
