package server

import (
        "errors"
        "net/http"
        "regexp"
        "path"

        valid "github.com/asaskevich/govalidator"
        "github.com/labstack/echo/v4"
        log "github.com/sirupsen/logrus"
        "github.com/spf13/viper"
        "github.com/ubccr/goipa"
        "github.com/ubccr/mokey/util"
)

func (h *Handler) changeMail(client *ipa.Client, user *ipa.UserRecord, mail string) error {
        uid := string(user.Uid)
        a, _ := regexp.Compile(viper.GetString("email_blacklist"))
        if a.MatchString(mail) || !valid.IsEmail(mail) {
                return errors.New("Le mail saisi n'est pas au bon format, ou n'est pas autorisé.")
        }
        if viper.GetBool("require_verify_email") {
                // Send user an email to verify their account
                err := h.emailer.SendVerifyNewEmail(uid, mail)
                if err != nil {
                        log.WithFields(log.Fields{
                                "err":   err,
                                "uid":   uid,
                                "email": mail,
                        }).Error("Failed to send to new email address")

                        // TODO: should we tell user about this?
                }
        }

        log.WithFields(log.Fields{
                "uid":   user,
                "email": mail,
        }).Warn("Succedeed to send to new email address")

        return nil
}

func (h *Handler) ChangeMail(c echo.Context) error {
        user := c.Get(ContextKeyUser).(*ipa.UserRecord)
        client := c.Get(ContextKeyIPAClient).(*ipa.Client)

        vars := map[string]interface{}{
                "user": user,
                "csrf": c.Get("csrf").(string),
        }

        if c.Request().Method == "POST" {
                mail := c.FormValue("new_mail")

                err := h.changeMail(client, user, mail)
                if err != nil {
                        vars["message"] = err.Error()
                } else {
                        vars["completed"] = true
                }
        }

        return c.Render(http.StatusOK, "change-mail.html", vars)
}

func (h *Handler) SetupMail(c echo.Context) error {
        _, tk := path.Split(c.Request().URL.Path)
        token, err := h.verifyToken(tk, util.VerifySalt, viper.GetInt("setup_max_age"))
        if err != nil {
                log.WithFields(log.Fields{
                        "error": err,
                        "token": tk,
                }).Error("Invalid token found")
                return echo.NewHTTPError(http.StatusNotFound, "Invalid token")
        }

        userRec, err := h.client.UserShow(token.UserName)
        if err != nil {
                log.WithFields(log.Fields{
                        "uid":   token.UserName,
                        "error": err,
                }).Error("Failed to fetch user record from freeipa")
                return echo.NewHTTPError(http.StatusInternalServerError, "Failed to get user")
        }

        vars := map[string]interface{}{
                "uid":   string(userRec.Uid),
                "email": token.Email,
                "csrf":  c.Get("csrf").(string),
        }

        if c.Request().Method == "POST" {
                // Change mail in FreeIPA
                err := h.client.ChangeMail(string(userRec.Uid), token.Email)
                if err != nil {
                        if ierr, ok := err.(*ipa.IpaError); ok {
                                log.WithFields(log.Fields{
                                        "uid":     string(userRec.Uid),
                                        "message": ierr.Message,
                                        "code":    ierr.Code,
                                }).Error("IPA Error changing mail")
                                return errors.New(ierr.Message)
                        }

                        log.WithFields(log.Fields{
                                "uid":   string(userRec.Uid),
                                "error": err.Error(),
                        }).Error("failed to set user mail in FreeIPA")
                        return errors.New("Fatal system error")
                }

                // Destroy token
                err = h.db.DestroyToken(token.Token)
                if err != nil {
                        log.WithFields(log.Fields{
                                "uid":   token.UserName,
                                "error": err,
                        }).Error("Failed to remove token from database")
                }

                vars["completed"] = true
        }

        return c.Render(http.StatusOK, "mail-changed.html", vars)
}
