package main
import (
    "database/sql"
    "net/http"
)
func main() {
    password := "hardcoded_secret_123" // Gosec/Gitleaks: Hardcoded credential
    db, _ := sql.Open("mysql", "user:"+password+"@/dbname")
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        user := r.URL.Query().Get("user")
        db.Exec("SELECT * FROM users WHERE name = '" + user + "'") // SQLi
    })
    http.ListenAndServe(":8080", nil)
}
