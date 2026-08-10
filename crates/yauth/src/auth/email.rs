use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::client::Tls;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

/// Host-supplied renderer for the four link mails this service sends, so the
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
}

#[derive(Clone)]
pub struct EmailService {
    /// The built async SMTP client. `AsyncSmtpTransport<Tokio1Executor>` is
    /// cheaply [`Clone`] (it shares one underlying connection pool), so the
    /// host may build the transport once at boot and hand a clone in via
    /// [`Self::with_transport`] — every consumer then shares one pool (F4).
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from_address: String,
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

    async fn send(&self, to: &str, subject: &str, body: String) -> Result<(), String> {
        let email = Message::builder()
            .from(
                self.from_address
                    .parse()
                    .map_err(|e| format!("Invalid from address: {}", e))?,
            )
            .to(to
                .parse()
                .map_err(|e| format!("Invalid to address: {}", e))?)
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(body)
            .map_err(|e| format!("Failed to build email: {}", e))?;

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
