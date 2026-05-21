# vxSafehome - Authentication Service

Spring Boot authentication microservice with JWT token-based authentication for mobile and web applications.

## 🔐 Features

- **OTP-based Authentication** - Email OTP verification for passwordless login
- **Password Authentication** - Traditional username/password login
- **JWT Tokens** - RS256 signed access and refresh tokens
- **Token Refresh** - Automatic token refresh flow for mobile apps
- **Fingerprinting** - Device fingerprinting for enhanced security
- **Login Attempt Tracking** - Account blocking after failed attempts
- **Mobile-First Design** - Token delivery via JSON (not cookies)

## 📚 Documentation

### Quick Links
- **[Quick Reference](QUICK_REFERENCE.md)** - Fast lookup for common tasks
- **[Token Handling Guide](TOKEN_HANDLING_GUIDE.md)** - Complete authentication flow
- **[API Contract](API_CONTRACT_MOBILE.md)** - Backend API specifications
- **[Flutter Implementation](FLUTTER_IMPLEMENTATION.md)** - Mobile app integration

### For Mobile Developers
Start with the **[Quick Reference](QUICK_REFERENCE.md)** for immediate implementation guidance.

### For Backend Developers
Review the **[Token Handling Guide](TOKEN_HANDLING_GUIDE.md)** for architecture details.

## 🚀 Quick Start

### Prerequisites
- Java 17+
- Maven 3.6+
- PostgreSQL database
- SMTP server (for OTP emails)

### Run the Application

```bash
# Clone the repository
git clone https://gitlab.vizuamatix.com:6009/ecl_blueprint/auth_service.git
cd auth_service

# Build
./mvnw clean install

# Run
./mvnw spring-boot:run
```

Application runs on: `http://localhost:8080`

## 📱 Mobile App Integration

### 1. Login Flow

```dart
// Request OTP
POST /Authservice/auth/sign-in
{
  "usernameOrEmail": "user@example.com"
}

// Verify OTP
POST /Authservice/auth/verify-otp-login
{
  "usernameOrEmail": "user@example.com",
  "otp": "123456"
}

// Response includes tokens
{
  "data": {
    "authData": {
      "access_token": "...",
      "refreshToken": "..."
    }
  }
}
```

### 2. Store Tokens Securely

```dart
final storage = FlutterSecureStorage();
await storage.write(key: 'access_token', value: accessToken);
await storage.write(key: 'refresh_token', value: refreshToken);
```

### 3. Use Tokens in Requests

```dart
headers: {
  'Authorization': 'Bearer $accessToken'
}
```

See **[Flutter Implementation](FLUTTER_IMPLEMENTATION.md)** for complete code examples.

## 🔧 Configuration

### Application Properties

```yaml
# Database
spring.datasource.url=jdbc:postgresql://localhost:5432/authdb
spring.datasource.username=your_username
spring.datasource.password=your_password

# JWT
jwt.expiration.access-token=300000  # 5 minutes
jwt.expiration.refresh-token=1296000000  # 15 days

# Email
spring.mail.host=smtp.gmail.com
spring.mail.username=your_email@gmail.com
spring.mail.password=your_app_password
```

## 🛡️ Security Features

- **RS256 JWT** - Asymmetric key signing
- **Short-lived Access Tokens** - 5 minute expiry
- **Long-lived Refresh Tokens** - 15 day expiry with database storage
- **Token Fingerprinting** - Prevents token theft
- **Login Attempt Blocking** - Automatic account protection
- **Secure Password Storage** - BCrypt hashing
- **CORS Configuration** - Controlled cross-origin access

## 🧪 Testing

```bash
# Run tests
./mvnw test

# Run with coverage
./mvnw clean test jacoco:report
```

### Test with Postman

Import the provided Postman collection or use:

```bash
# Sign in
curl -X POST http://localhost:8080/Authservice/auth/sign-in \
  -H "Content-Type: application/json" \
  -d '{"usernameOrEmail": "user@example.com"}'

# Verify OTP
curl -X POST http://localhost:8080/Authservice/auth/verify-otp-login \
  -H "Content-Type: application/json" \
  -d '{"usernameOrEmail": "user@example.com", "otp": "123456"}'
```

## 📊 Project Structure

```
src/main/java/com/auth/service/
├── config/          # Security, CORS, JWT configuration
├── controller/      # REST API endpoints
├── dto/             # Data transfer objects
├── entity/          # JPA entities
├── repository/      # Database repositories
├── service/         # Business logic
├── exception/       # Custom exceptions
└── util/            # Utility classes
```

## 🔑 Key Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/sign-in` | POST | Request OTP |
| `/auth/verify-otp-login` | POST | Verify OTP & login |
| `/auth/password/sign-in` | POST | Password login |
| `/auth/refresh-token` | POST | Refresh access token |
| `/auth/logout` | POST | Logout & revoke tokens |

See **[API Contract](API_CONTRACT_MOBILE.md)** for complete API documentation.

## 🤝 Contributing

1. Create a feature branch
2. Make your changes
3. Write/update tests
4. Submit a merge request

## 📄 License

Proprietary - VizuaMatix

## 📞 Support

For issues or questions:
- Review the documentation files
- Check the code examples
- Contact the development team

---

**Last Updated:** January 2, 2026  
**Version:** 1.0  
**Maintained by:** VizuaMatix - vxSafehome Team

## Add your files

- [ ] [Create](https://docs.gitlab.com/ee/user/project/repository/web_editor.html#create-a-file) or [upload](https://docs.gitlab.com/ee/user/project/repository/web_editor.html#upload-a-file) files
- [ ] [Add files using the command line](https://docs.gitlab.com/ee/gitlab-basics/add-file.html#add-a-file-using-the-command-line) or push an existing Git repository with the following command:

```
cd existing_repo
git remote add origin https://gitlab.vizuamatix.com:6009/ecl_blueprint/auth_service.git
git branch -M main
git push -uf origin main
```

## Integrate with your tools

- [ ] [Set up project integrations](https://gitlab.vizuamatix.com:6009/ecl_blueprint/auth_service/-/settings/integrations)

## Collaborate with your team

- [ ] [Invite team members and collaborators](https://docs.gitlab.com/ee/user/project/members/)
- [ ] [Create a new merge request](https://docs.gitlab.com/ee/user/project/merge_requests/creating_merge_requests.html)
- [ ] [Automatically close issues from merge requests](https://docs.gitlab.com/ee/user/project/issues/managing_issues.html#closing-issues-automatically)
- [ ] [Enable merge request approvals](https://docs.gitlab.com/ee/user/project/merge_requests/approvals/)
- [ ] [Set auto-merge](https://docs.gitlab.com/ee/user/project/merge_requests/merge_when_pipeline_succeeds.html)

## Test and Deploy

Use the built-in continuous integration in GitLab.

- [ ] [Get started with GitLab CI/CD](https://docs.gitlab.com/ee/ci/quick_start/index.html)
- [ ] [Analyze your code for known vulnerabilities with Static Application Security Testing (SAST)](https://docs.gitlab.com/ee/user/application_security/sast/)
- [ ] [Deploy to Kubernetes, Amazon EC2, or Amazon ECS using Auto Deploy](https://docs.gitlab.com/ee/topics/autodevops/requirements.html)
- [ ] [Use pull-based deployments for improved Kubernetes management](https://docs.gitlab.com/ee/user/clusters/agent/)
- [ ] [Set up protected environments](https://docs.gitlab.com/ee/ci/environments/protected_environments.html)

***

# Editing this README

When you're ready to make this README your own, just edit this file and use the handy template below (or feel free to structure it however you want - this is just a starting point!). Thanks to [makeareadme.com](https://www.makeareadme.com/) for this template.

## Suggestions for a good README

Every project is different, so consider which of these sections apply to yours. The sections used in the template are suggestions for most open source projects. Also keep in mind that while a README can be too long and detailed, too long is better than too short. If you think your README is too long, consider utilizing another form of documentation rather than cutting out information.

## Name
Choose a self-explaining name for your project.

## Description
Let people know what your project can do specifically. Provide context and add a link to any reference visitors might be unfamiliar with. A list of Features or a Background subsection can also be added here. If there are alternatives to your project, this is a good place to list differentiating factors.

## Badges
On some READMEs, you may see small images that convey metadata, such as whether or not all the tests are passing for the project. You can use Shields to add some to your README. Many services also have instructions for adding a badge.

## Visuals
Depending on what you are making, it can be a good idea to include screenshots or even a video (you'll frequently see GIFs rather than actual videos). Tools like ttygif can help, but check out Asciinema for a more sophisticated method.

## Installation
Within a particular ecosystem, there may be a common way of installing things, such as using Yarn, NuGet, or Homebrew. However, consider the possibility that whoever is reading your README is a novice and would like more guidance. Listing specific steps helps remove ambiguity and gets people to using your project as quickly as possible. If it only runs in a specific context like a particular programming language version or operating system or has dependencies that have to be installed manually, also add a Requirements subsection.

## Usage
Use examples liberally, and show the expected output if you can. It's helpful to have inline the smallest example of usage that you can demonstrate, while providing links to more sophisticated examples if they are too long to reasonably include in the README.

## Support
Tell people where they can go to for help. It can be any combination of an issue tracker, a chat room, an email address, etc.

## Roadmap
If you have ideas for releases in the future, it is a good idea to list them in the README.

## Contributing
State if you are open to contributions and what your requirements are for accepting them.

For people who want to make changes to your project, it's helpful to have some documentation on how to get started. Perhaps there is a script that they should run or some environment variables that they need to set. Make these steps explicit. These instructions could also be useful to your future self.

You can also document commands to lint the code or run tests. These steps help to ensure high code quality and reduce the likelihood that the changes inadvertently break something. Having instructions for running tests is especially helpful if it requires external setup, such as starting a Selenium server for testing in a browser.

## Authors and acknowledgment
Show your appreciation to those who have contributed to the project.

## License
For open source projects, say how it is licensed.

## Project status
If you have run out of energy or time for your project, put a note at the top of the README saying that development has slowed down or stopped completely. Someone may choose to fork your project or volunteer to step in as a maintainer or owner, allowing your project to keep going. You can also make an explicit request for maintainers.
