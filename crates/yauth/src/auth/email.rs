use lettre::message::header::{HeaderName, HeaderValue};
use lettre::message::{Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::Tls;
use lettre::{Address, AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

/// Host-supplied renderer for the five link mails this service sends, so the
/// embedding application can brand them without forking the templates.
///
/// Each method returns `(subject, body_html)`. The host receives the fully
/// built one-time URL; it must escape it into its own markup. When no renderer
/// is installed (via `YAuthBuilder::with_email_templates`), the built-in
/// unbranded defaults below are used, so this is additive.
pub trait AuthEmailTemplates: Send + Sync {
    fn verification(&self, verify_url: &str) -> (String, String);
    fn magic_link(&self, magic_url: &str) -> (String, String);
    fn password_reset(&self, reset_url: &str) -> (String, String);
    fn unlock(&self, unlock_url: &str) -> (String, String);
    /// Sent when a registration attempt hits an email that already has a
    /// verified account. `reset_url` is a freshly minted password-reset link
    /// so the (presumably password-forgetting) owner can get back in.
    fn already_registered(&self, reset_url: &str) -> (String, String);

    /// A `text/plain` rendering of one of the bodies above. `Some` makes the
    /// message `multipart/alternative` — text part first, HTML second — for
    /// text-only clients and for mailbox providers that score HTML-only mail
    /// down; `None` (the default) sends the HTML part alone. The host owns the
    /// markup, so it owns the conversion too; the built-in templates carry no
    /// text alternative.
    fn plain_text_alternative(&self, _body_html: &str) -> Option<String> {
        None
    }
}

#[derive(Clone)]
pub struct EmailService {
    /// The built async SMTP client. `AsyncSmtpTransport<Tokio1Executor>` is
    /// cheaply [`Clone`] (it shares one underlying connection pool), so the
    /// host may build the transport once at boot and hand a clone in via
    /// [`Self::with_transport`] — every consumer then shares one pool (F4).
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from_address: String,
    /// Display name on the `From` header (`Name <from_address>`); `None`
    /// sends the bare address. See [`Self::with_from_name`].
    from_name: Option<String>,
    /// `Reply-To` address; `None` sets no such header. See
    /// [`Self::with_reply_to`].
    reply_to: Option<String>,
    app_url: String,
    /// Host-supplied branded templates; `None` uses the built-in defaults.
    templates: Option<std::sync::Arc<dyn AuthEmailTemplates>>,
}

impl EmailService {
    /// Build the service from raw SMTP settings — the config-driven path
    /// `YAuthBuilder::build()` takes when no transport is injected. The
    /// credentials-vs-plaintext transport is built **once here** (it used to
    /// be rebuilt on every [`Self::send`]) and stored.
    pub fn new(
        smtp_host: String,
        smtp_port: u16,
        from_address: String,
        app_url: String,
        username: Option<String>,
        password: Option<String>,
    ) -> Self {
        let transport = Self::build_transport(&smtp_host, smtp_port, username, password);
        Self {
            transport,
            from_address,
            from_name: None,
            reply_to: None,
            app_url,
            templates: None,
        }
    }

    /// Install host-supplied branded templates for the four link mails.
    #[must_use]
    pub fn with_templates(mut self, templates: std::sync::Arc<dyn AuthEmailTemplates>) -> Self {
        self.templates = Some(templates);
        self
    }

    /// Display name for the `From` header — `Name <from_address>` instead of
    /// the bare address, which mailbox providers (and the AWS SES
    /// production-access review) read as a hygiene signal. Blank ⇒ the bare
    /// address. Fed from `SmtpConfig::from_name` by the builder.
    #[must_use]
    pub fn with_from_name(mut self, from_name: Option<String>) -> Self {
        self.from_name = non_blank(from_name);
        self
    }

    /// `Reply-To` address for every message — a monitored mailbox a
    /// recipient's reply reaches when the sending address is unmonitored.
    /// Blank ⇒ no `Reply-To` header. Fed from `SmtpConfig::reply_to` by the
    /// builder.
    #[must_use]
    pub fn with_reply_to(mut self, reply_to: Option<String>) -> Self {
        self.reply_to = non_blank(reply_to);
        self
    }

    /// Build the service from an already-constructed transport — the F4
    /// shared-pool path. The host builds one
    /// `AsyncSmtpTransport<Tokio1Executor>` at boot and clones it into both
    /// this service and any other consumer (the casino admin mailer), so all
    /// of them share a single connection pool.
    pub fn with_transport(
        transport: AsyncSmtpTransport<Tokio1Executor>,
        from_address: String,
        app_url: String,
    ) -> Self {
        Self {
            transport,
            from_address,
            from_name: None,
            reply_to: None,
            app_url,
            templates: None,
        }
    }

    /// The credentials-vs-plaintext transport selection (unchanged from the
    /// branching that used to live inline in [`Self::send`]).
    ///
    /// R1 patch: with credentials, use an authenticated STARTTLS relay (the
    /// AWS SES SMTP endpoint and any real relay require this). Without them,
    /// keep the original unauthenticated plaintext path (docker-compose
    /// mailpit), so dev wiring is untouched. F3: the transport is the async
    /// lettre client so sends never block the tokio worker.
    fn build_transport(
        smtp_host: &str,
        smtp_port: u16,
        username: Option<String>,
        password: Option<String>,
    ) -> AsyncSmtpTransport<Tokio1Executor> {
        match (username, password) {
            (Some(username), Some(password)) => {
                // `starttls_relay` only fails when the platform has no TLS
                // backend compiled in; mirror the previous behaviour by
                // surfacing that as a panic at build time rather than per send.
                AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(smtp_host)
                    .expect("Failed to build SMTP relay")
                    .port(smtp_port)
                    .credentials(Credentials::new(username, password))
                    .build()
            }
            _ => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(smtp_host)
                .port(smtp_port)
                .tls(Tls::None)
                .build(),
        }
    }

    /// Build the message [`Self::send`] submits, without sending it — public
    /// so a host can assert the headers and body structure it configured
    /// through this service without an SMTP round trip.
    ///
    /// Every message carries the same sender identity and hygiene headers:
    /// `From` with the configured display name, `Reply-To` when configured, a
    /// `Message-ID` minted under the `From` domain (`<uuid@domain>` — lettre
    /// does not add one, and a relay-assigned id would sit under the relay's
    /// hostname), `Auto-Submitted: auto-generated` (RFC 3834: a machine
    /// generated this one-time link, so auto-responders should not answer
    /// it), and `MIME-Version: 1.0`. The body is `multipart/alternative`,
    /// text part first, when the installed templates supply an
    /// [`AuthEmailTemplates::plain_text_alternative`], and a single
    /// `text/html` part otherwise.
    pub fn build_message(
        &self,
        to: &str,
        subject: &str,
        body_html: String,
    ) -> Result<Message, String> {
        let from_address: Address = self
            .from_address
            .trim()
            .parse()
            .map_err(|e| format!("Invalid from address: {e}"))?;
        let message_id = format!("<{}@{}>", uuid::Uuid::now_v7(), from_address.domain());
        let mut builder = Message::builder()
            .from(Mailbox::new(self.from_name.clone(), from_address))
            .to(to.parse().map_err(|e| format!("Invalid to address: {e}"))?)
            .subject(subject)
            .message_id(Some(message_id))
            .raw_header(HeaderValue::new(
                HeaderName::new_from_ascii_str("Auto-Submitted"),
                "auto-generated".to_string(),
            ));
        if let Some(reply_to) = &self.reply_to {
            builder = builder.reply_to(
                reply_to
                    .parse()
                    .map_err(|e| format!("Invalid reply-to address: {e}"))?,
            );
        }

        let plain_text = self
            .templates
            .as_ref()
            .and_then(|templates| templates.plain_text_alternative(&body_html))
            .filter(|text| !text.trim().is_empty());
        let message = match plain_text {
            Some(text) => builder.multipart(MultiPart::alternative_plain_html(text, body_html)),
            None => builder.singlepart(SinglePart::html(body_html)),
        };
        message.map_err(|e| format!("Failed to build email: {e}"))
    }

    async fn send(&self, to: &str, subject: &str, body: String) -> Result<(), String> {
        let email = self.build_message(to, subject, body)?;

        self.transport
            .send(email)
            .await
            .map_err(|e| format!("Failed to send email: {}", e))?;

        Ok(())
    }

    pub async fn send_verification_email(&self, to: &str, token: &str) -> Result<(), String> {
        let verify_url = format!("{}/verify-email?token={}", self.app_url, token);

        if let Some(templates) = &self.templates {
            let (subject, body) = templates.verification(&verify_url);
            self.send(to, &subject, body).await?;
            crate::otel::add_event(
                "verification_email_sent",
                #[cfg(feature = "telemetry")]
                vec![opentelemetry::KeyValue::new("email.to", to.to_string())],
                #[cfg(not(feature = "telemetry"))]
                vec![],
            );
            return Ok(());
        }

        let body = format!(
            r#"<!DOCTYPE html>
<html>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
  <h2 style="color: #1a1a1a;">Verify your email address</h2>
  <p style="color: #4a4a4a; line-height: 1.6;">
    Thanks for signing up! Please click the button below to verify your email address.
  </p>
  <div style="margin: 30px 0;">
    <a href="{verify_url}" style="background-color: #18181b; color: #fafafa; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 500;">
      Verify Email
    </a>
  </div>
  <p style="color: #6a6a6a; font-size: 14px;">
    Or copy and paste this link: <br/>
    <a href="{verify_url}" style="color: #18181b;">{verify_url}</a>
  </p>
  <p style="color: #9a9a9a; font-size: 12px; margin-top: 40px;">
    This link expires in 24 hours. If you didn't create an account, you can ignore this email.
  </p>
</body>
</html>"#
        );

        self.send(to, "Verify your email address", body).await?;

        crate::otel::add_event(
            "verification_email_sent",
            #[cfg(feature = "telemetry")]
            vec![opentelemetry::KeyValue::new("email.to", to.to_string())],
            #[cfg(not(feature = "telemetry"))]
            vec![],
        );
        Ok(())
    }

    pub async fn send_magic_link_email(&self, to: &str, token: &str) -> Result<(), String> {
        let magic_url = format!("{}/auth/magic-link/verify?token={}", self.app_url, token);

        if let Some(templates) = &self.templates {
            let (subject, body) = templates.magic_link(&magic_url);
            self.send(to, &subject, body).await?;
            crate::otel::add_event(
                "magic_link_email_sent",
                #[cfg(feature = "telemetry")]
                vec![opentelemetry::KeyValue::new("email.to", to.to_string())],
                #[cfg(not(feature = "telemetry"))]
                vec![],
            );
            return Ok(());
        }

        let body = format!(
            r#"<!DOCTYPE html>
<html>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
  <h2 style="color: #1a1a1a;">Sign in to your account</h2>
  <p style="color: #4a4a4a; line-height: 1.6;">
    Click the button below to sign in. This link will expire in 5 minutes.
  </p>
  <div style="margin: 30px 0;">
    <a href="{magic_url}" style="background-color: #18181b; color: #fafafa; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 500;">
      Sign In
    </a>
  </div>
  <p style="color: #6a6a6a; font-size: 14px;">
    Or copy and paste this link: <br/>
    <a href="{magic_url}" style="color: #18181b;">{magic_url}</a>
  </p>
  <p style="color: #9a9a9a; font-size: 12px; margin-top: 40px;">
    If you didn't request this link, you can safely ignore this email.
  </p>
</body>
</html>"#
        );

        self.send(to, "Sign in to your account", body).await?;

        crate::otel::add_event(
            "magic_link_email_sent",
            #[cfg(feature = "telemetry")]
            vec![opentelemetry::KeyValue::new("email.to", to.to_string())],
            #[cfg(not(feature = "telemetry"))]
            vec![],
        );
        Ok(())
    }

    pub async fn send_password_reset_email(&self, to: &str, token: &str) -> Result<(), String> {
        let reset_url = format!("{}/reset-password?token={}", self.app_url, token);

        if let Some(templates) = &self.templates {
            let (subject, body) = templates.password_reset(&reset_url);
            self.send(to, &subject, body).await?;
            crate::otel::add_event(
                "password_reset_email_sent",
                #[cfg(feature = "telemetry")]
                vec![opentelemetry::KeyValue::new("email.to", to.to_string())],
                #[cfg(not(feature = "telemetry"))]
                vec![],
            );
            return Ok(());
        }

        let body = format!(
            r#"<!DOCTYPE html>
<html>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
  <h2 style="color: #1a1a1a;">Reset your password</h2>
  <p style="color: #4a4a4a; line-height: 1.6;">
    We received a request to reset your password. Click the button below to choose a new password.
  </p>
  <div style="margin: 30px 0;">
    <a href="{reset_url}" style="background-color: #18181b; color: #fafafa; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 500;">
      Reset Password
    </a>
  </div>
  <p style="color: #6a6a6a; font-size: 14px;">
    Or copy and paste this link: <br/>
    <a href="{reset_url}" style="color: #18181b;">{reset_url}</a>
  </p>
  <p style="color: #9a9a9a; font-size: 12px; margin-top: 40px;">
    This link expires in 1 hour. If you didn't request a password reset, you can ignore this email.
  </p>
</body>
</html>"#
        );

        self.send(to, "Reset your password", body).await?;

        crate::otel::add_event(
            "password_reset_email_sent",
            #[cfg(feature = "telemetry")]
            vec![opentelemetry::KeyValue::new("email.to", to.to_string())],
            #[cfg(not(feature = "telemetry"))]
            vec![],
        );
        Ok(())
    }

    /// The mail behind the enumeration-safe duplicate-register path: the
    /// address already has a verified account, so instead of silence the
    /// owner gets told they have an account, with a password-reset link in
    /// case a forgotten password is why they tried to sign up again.
    pub async fn send_already_registered_email(&self, to: &str, token: &str) -> Result<(), String> {
        let reset_url = format!("{}/reset-password?token={}", self.app_url, token);

        if let Some(templates) = &self.templates {
            let (subject, body) = templates.already_registered(&reset_url);
            self.send(to, &subject, body).await?;
            crate::otel::add_event(
                "already_registered_email_sent",
                #[cfg(feature = "telemetry")]
                vec![opentelemetry::KeyValue::new("email.to", to.to_string())],
                #[cfg(not(feature = "telemetry"))]
                vec![],
            );
            return Ok(());
        }

        let body = format!(
            r#"<!DOCTYPE html>
<html>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
  <h2 style="color: #1a1a1a;">You already have an account</h2>
  <p style="color: #4a4a4a; line-height: 1.6;">
    Someone — hopefully you — tried to sign up with this email address, but an
    account already exists for it. You can sign in with your existing password,
    or reset it below if you've forgotten it.
  </p>
  <div style="margin: 30px 0;">
    <a href="{reset_url}" style="background-color: #18181b; color: #fafafa; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 500;">
      Reset Password
    </a>
  </div>
  <p style="color: #6a6a6a; font-size: 14px;">
    Or copy and paste this link: <br/>
    <a href="{reset_url}" style="color: #18181b;">{reset_url}</a>
  </p>
  <p style="color: #9a9a9a; font-size: 12px; margin-top: 40px;">
    This link expires in 1 hour. If this wasn't you, no action is needed — your
    account is unchanged and your password still works.
  </p>
</body>
</html>"#
        );

        self.send(to, "You already have an account", body).await?;

        crate::otel::add_event(
            "already_registered_email_sent",
            #[cfg(feature = "telemetry")]
            vec![opentelemetry::KeyValue::new("email.to", to.to_string())],
            #[cfg(not(feature = "telemetry"))]
            vec![],
        );
        Ok(())
    }

    pub async fn send_unlock_email(&self, to: &str, unlock_url: &str) -> Result<(), String> {
        if let Some(templates) = &self.templates {
            let (subject, body) = templates.unlock(unlock_url);
            return self.send(to, &subject, body).await;
        }

        let body = format!(
            r#"<!DOCTYPE html>
<html>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
  <h2 style="color: #1a1a1a;">Unlock your account</h2>
  <p style="color: #4a4a4a; line-height: 1.6;">
    Your account has been locked due to too many failed login attempts.
    Click the button below to unlock your account.
  </p>
  <div style="margin: 30px 0;">
    <a href="{unlock_url}" style="background-color: #18181b; color: #fafafa; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: 500;">
      Unlock Account
    </a>
  </div>
  <p style="color: #6a6a6a; font-size: 14px;">
    Or copy and paste this link: <br/>
    <a href="{unlock_url}" style="color: #18181b;">{unlock_url}</a>
  </p>
  <p style="color: #9a9a9a; font-size: 12px; margin-top: 40px;">
    This link expires in 1 hour. If you didn't request this, you can safely ignore this email.
  </p>
</body>
</html>"#
        );

        self.send(to, "Unlock your account", body).await?;
        Ok(())
    }
}

/// Trim an optional knob and treat blank as unset.
fn non_blank(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `builder_dangerous` opens no connection until a send, so a closed port
    /// is fine for building messages.
    fn service() -> EmailService {
        EmailService::new(
            "127.0.0.1".to_string(),
            1,
            "noreply@yauth.test".to_string(),
            "http://localhost:3000".to_string(),
            None,
            None,
        )
    }

    fn wire(message: Message) -> String {
        String::from_utf8(message.formatted()).expect("message is valid UTF-8")
    }

    fn header<'a>(wire: &'a str, name: &str) -> Option<&'a str> {
        wire.lines().find(|line| line.starts_with(name))
    }

    /// Test-only templates that render a text alternative.
    struct PlainTextTemplates;

    impl AuthEmailTemplates for PlainTextTemplates {
        fn verification(&self, verify_url: &str) -> (String, String) {
            ("Verify".to_string(), format!("<p>Verify: {verify_url}</p>"))
        }

        fn magic_link(&self, magic_url: &str) -> (String, String) {
            ("Sign in".to_string(), format!("<p>{magic_url}</p>"))
        }

        fn password_reset(&self, reset_url: &str) -> (String, String) {
            ("Reset".to_string(), format!("<p>{reset_url}</p>"))
        }

        fn unlock(&self, unlock_url: &str) -> (String, String) {
            ("Unlock".to_string(), format!("<p>{unlock_url}</p>"))
        }

        fn already_registered(&self, reset_url: &str) -> (String, String) {
            ("Registered".to_string(), format!("<p>{reset_url}</p>"))
        }

        fn plain_text_alternative(&self, body_html: &str) -> Option<String> {
            Some(body_html.replace("<p>", "").replace("</p>", ""))
        }
    }

    #[test]
    fn messages_carry_the_sender_identity_and_hygiene_headers() {
        let message = service()
            .with_from_name(Some("YAuth".to_string()))
            .with_reply_to(Some("support@yauth.test".to_string()))
            .build_message(
                "user@example.com",
                "Verify your email address",
                "<p>Hello</p>".to_string(),
            )
            .expect("build message");
        let wire = wire(message);

        assert_eq!(
            header(&wire, "From:"),
            Some("From: YAuth <noreply@yauth.test>")
        );
        assert_eq!(
            header(&wire, "Reply-To:"),
            Some("Reply-To: support@yauth.test")
        );
        assert_eq!(
            header(&wire, "Auto-Submitted:"),
            Some("Auto-Submitted: auto-generated")
        );
        let message_id = header(&wire, "Message-ID:").expect("Message-ID header");
        assert!(
            message_id.starts_with("Message-ID: <") && message_id.ends_with("@yauth.test>"),
            "minted under the From domain: {message_id}"
        );
        assert_eq!(header(&wire, "MIME-Version:"), Some("MIME-Version: 1.0"));
        assert!(wire.contains("Content-Type: text/html"), "{wire}");
        assert!(
            !wire.contains("multipart/alternative"),
            "the built-in templates carry no text alternative: {wire}"
        );
    }

    #[test]
    fn blank_identity_knobs_send_the_bare_address_and_no_reply_to() {
        let message = service()
            .with_from_name(Some("   ".to_string()))
            .with_reply_to(Some(String::new()))
            .build_message("user@example.com", "Subject", "<p>Hello</p>".to_string())
            .expect("build message");
        let wire = wire(message);

        assert_eq!(header(&wire, "From:"), Some("From: noreply@yauth.test"));
        assert_eq!(header(&wire, "Reply-To:"), None);
    }

    #[test]
    fn a_host_text_alternative_makes_the_body_multipart_text_first() {
        let message = service()
            .with_templates(std::sync::Arc::new(PlainTextTemplates))
            .build_message(
                "user@example.com",
                "Verify",
                "<p>Verify: https://example.com/verify</p>".to_string(),
            )
            .expect("build message");
        let wire = wire(message);

        assert!(
            wire.contains("Content-Type: multipart/alternative"),
            "{wire}"
        );
        let plain = wire.find("Content-Type: text/plain").expect("text part");
        let html = wire.find("Content-Type: text/html").expect("HTML part");
        assert!(plain < html, "the text part precedes the HTML part: {wire}");
        assert!(
            wire[plain..html].contains("Verify: https://example.com/verify"),
            "{wire}"
        );
    }

    #[test]
    fn message_ids_are_unique_per_build() {
        let service = service();
        let first = wire(
            service
                .build_message("user@example.com", "Subject", "<p>a</p>".to_string())
                .expect("build first"),
        );
        let second = wire(
            service
                .build_message("user@example.com", "Subject", "<p>b</p>".to_string())
                .expect("build second"),
        );
        let first_id = header(&first, "Message-ID:").expect("first Message-ID");
        let second_id = header(&second, "Message-ID:").expect("second Message-ID");
        assert_ne!(first_id, second_id);
    }
}
