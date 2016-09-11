# oauth-server
Example how  to use google oauth for implementing authentification with google/
In application.properties file replace two lines:
```
google.client.id=<enter_your_id>
google.client.secret=<enter_your_secret>
```
Start application by running main method in OauthServerApplication class or just run gradle task bootRun.
Application will be accessible through url: localhost:9000