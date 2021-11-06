package server

import (
        "errors"
        "fmt"
        "regexp"
        "net/http"
        "path/filepath"
        "strings"
	"unicode"

        valid "github.com/asaskevich/govalidator"
        "github.com/dchest/captcha"
        "github.com/labstack/echo-contrib/session"
        "github.com/labstack/echo/v4"
        log "github.com/sirupsen/logrus"
        "github.com/spf13/viper"
        "github.com/ubccr/goipa"
        "github.com/ubccr/mokey/util"
        "golang.org/x/text/transform"
        "golang.org/x/text/unicode/norm"
        "golang.org/x/text/runes"
)

func init() {
        viper.SetDefault("enable_user_signup", true)
        viper.SetDefault("enable_captcha", true)
        viper.SetDefault("default_shell", "/bin/bash")
        viper.SetDefault("default_homedir", "/home")
        viper.SetDefault("login_regex", "^[0-9]*$")
        viper.SetDefault("email_blacklist", "^$")
}

func removeAccents(s string) string  {
	t := transform.Chain(norm.NFD, runes.Remove(runes.In(unicode.Mn)), norm.NFC)
	output, _, e := transform.String(t, s)
	if e != nil {
		panic(e)
	}
	return output
}

// Create new user account POST handler
func (h *Handler) CreateAccount(c echo.Context) error {
        vars := map[string]interface{}{
                "csrf":                 c.Get("csrf").(string),
                "require_verify_email": viper.GetBool("require_verify_email"),
        }

        uid := c.FormValue("uid")
        if viper.GetBool("globus_signup") {
                username, err := h.globusUsername(c)
                if err != nil {
                        log.WithFields(log.Fields{
                                "err": err,
                        }).Error("Signup requires globus authentication")
                        return c.Redirect(http.StatusFound, Path("/auth/globus"))
                }
                uid = username
                vars["globus_user"] = uid
        }

        email := strings.TrimSpace(c.FormValue("email"))
        email2 := strings.TrimSpace(c.FormValue("email2"))
        first := strings.TrimSpace(c.FormValue("first"))
        last := removeAccents(strings.ToUpper(strings.TrimSpace(c.FormValue("last"))))
        pass := c.FormValue("password")
        pass2 := c.FormValue("password2")
        celarstatut := c.FormValue("celarstatut")
        captchaID := c.FormValue("captcha_id")
        captchaSol := c.FormValue("captcha_sol")

        if viper.GetBool("enable_captcha") {
                vars["captchaID"] = captcha.New()
        }

        err := h.createAccount(uid, email, email2, first, last, pass, pass2, celarstatut, captchaID, captchaSol)
        if err != nil {
                vars["message"] = err.Error()
        } else {
                logout(c)
                vars["success"] = true
        }

        return c.Render(http.StatusOK, "signup.html", vars)
}

func (h *Handler) globusUsername(c echo.Context) (string, error) {
        sess, err := session.Get(CookieKeySession, c)
        if err != nil {
                return "", errors.New("failed to get session")
        }

        globus := sess.Values[CookieKeyGlobus]
        globusUser := sess.Values[CookieKeyGlobusUsername]

        if globus == nil || globusUser == nil {
                return "", errors.New("no globus user in session")
        }

        if _, ok := globusUser.(string); !ok {
                return "", errors.New("globus user is not string")
        }

        if _, ok := globus.(bool); !ok || !globus.(bool) {
                return "", errors.New("no globus flag is not bool true")
        }

        username := globusUser.(string)
        if len(username) == 0 {
                return "", errors.New("globus username is empty")
        }

        return username, nil
}

// Signup form GET handler
func (h *Handler) Signup(c echo.Context) error {
        vars := map[string]interface{}{
                "csrf": c.Get("csrf").(string),
        }

        if viper.GetBool("globus_signup") {
                username, err := h.globusUsername(c)
                if err != nil {
                        log.WithFields(log.Fields{
                                "err": err,
                        }).Error("Signup requires globus authentication")
                        return c.Redirect(http.StatusFound, Path("/auth/globus"))
                }
                vars["globus_user"] = username
        }

        if viper.GetBool("enable_captcha") {
                vars["captchaID"] = captcha.New()
        }

        return c.Render(http.StatusOK, "signup.html", vars)
}

// createAccount does the work of validation and creating the account in FreeIPA
func (h *Handler) createAccount(uid, email, email2, first, last, pass, pass2, celarstatut, captchaID, captchaSol string) error {
        //if !valid.IsEmail(email) {
        //      return errors.New("Please provide a valid email address")
        //}
        a, _ := regexp.Compile(viper.GetString("email_blacklist"))
        if a.MatchString(email) || !valid.IsEmail(email) {
                return errors.New("Le mail saisi n'est pas au bon format, ou n'est pas autorisé!")
        }

        if email != email2 {
                return errors.New("Les deux adresses mail ne correspondent pas.")
        }

        if len(uid) <= 1 || len(uid) > 50 {
                return errors.New("Merci de saisir un login.")
        }

        //if !valid.IsAlphanumeric(uid) {
        //      return errors.New("Username must be alpha numeric")
        //}
        r, _ := regexp.Compile(viper.GetString("login_regex"))
        if !r.MatchString(uid) {
                return errors.New("Le login saisi n'est pas au bon format!")
        }
        if len(first) == 0 || len(first) > 150 {
                return errors.New("Merci de saisir votre prénom.")
        }

        if len(last) == 0 || len(last) > 150 {
                return errors.New("Merci de saisir votre nom.")
        }

        if err := util.CheckPassword(pass, viper.GetInt("min_passwd_len"), viper.GetInt("min_passwd_classes")); err != nil {
                return err
        }

        if pass != pass2 {
                return errors.New("Les deux mots de passe ne correspondent pas!")
        }

        if viper.GetBool("enable_captcha") {
                if len(captchaID) == 0 {
                        return errors.New("Invalid captcha provided")
                }
                if len(captchaSol) == 0 {
                        return errors.New("Please type in the numbers you see in the picture")
                }

                if !captcha.VerifyString(captchaID, captchaSol) {
                        return errors.New("The numbers you typed in do not match the image")
                }
        }

        homedir := filepath.Join(viper.GetString("default_homedir"), uid)

        mailcount, err := h.client.MailFind(email)
        if mailcount > 0 {
                return errors.New("L'adresse mail a déjà été enregistrée.")
                log.WithFields(log.Fields{"code": "200"}).Warning("mailcount: ", mailcount)
        }

        userRec, err := h.client.UserAdd(uid, email, first, last, homedir, viper.GetString("default_shell"), true)
        if err != nil {
                if ierr, ok := err.(*ipa.IpaError); ok {
                        if ierr.Code == 4002 {
                                return fmt.Errorf("Ce login existe déjà: %s", uid)
                        } else {
                                log.WithFields(log.Fields{
                                        "code": ierr.Code,
                                }).Error("Erreur inconnue lors de la création sur le serveur de comptes.")
                        }
                }

                log.WithFields(log.Fields{
                        "err":     err,
                        "uid":     uid,
                        "email":   email,
                        "first":   first,
                        "last":    last,
                        "homedir": homedir,
                }).Error("Failed to create user account")
                return errors.New("Failed to create user account. Fatal system error.")
        }

        log.WithFields(log.Fields{
                "uid":     uid,
                "email":   email,
                "first":   first,
                "last":    last,
                "homedir": homedir,
        }).Warn("New user account created")

        // Set password
        err = h.client.SetPassword(uid, userRec.Randompassword, pass, "")
        if err != nil {
                log.WithFields(log.Fields{
                        "err":   err,
                        "uid":   uid,
                        "email": email,
                }).Error("Failed to set password for user")

                // TODO: need to handle this case better
                return errors.New("There was a problem creating your account. Please contact the administrator")
        }

        log.WithFields(log.Fields{
                "uid": uid,
        }).Warn("User password set successfully")

        if viper.GetBool("require_verify_email") {
                // Disable new users until they have verified their email address
                err = h.client.UserDisable(uid)
                if err != nil {
                        log.WithFields(log.Fields{
                                "err": err,
                                "uid": uid,
                        }).Error("Failed to disable user")

                        // TODO: should we tell user about this? probably not?
                }

                // Send user an email to verify their account
                err = h.emailer.SendVerifyAccountEmail(uid, email)
                if err != nil {
                        log.WithFields(log.Fields{
                                "err":   err,
                                "uid":   uid,
                                "email": email,
                        }).Error("Failed to send new account email")

                        // TODO: should we tell user about this?
                } else {
                        log.WithFields(log.Fields{
                                "uid":   uid,
                                "email": email,
                        }).Warn("New user account email sent successfully")
                }
        }

        return nil
}
