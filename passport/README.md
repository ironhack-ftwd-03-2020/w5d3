# Passport - authentication middleware for node js

Good Explanation of (de)serialize in passport:

https://stackoverflow.com/questions/27637609/understanding-passport-serialize-deserialize


Github Passport Strategy : 

https://github.com/jaredhanson/passport-github

Passport explained in depth:

https://www.airpair.com/express/posts/expressjs-and-passportjs-sessions-deep-dive 

The different forms of authentication are called strategies in passport

# Passport Local Strategy

We will use username and password first: http://www.passportjs.org/docs/username-password/

```
$ npm install passport passport-local
```

```
// app.js
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
```

```
// app.js  -   put further down -  before express view engine setup
app.use(passport.initialize());
app.use(passport.session());
```

Now we need to add 3 things serialize and deserialize user and the strategy

```
// we serialize only the `_id` field of the user to keep the information stored minimum
passport.serializeUser((user, done) => {
  done(null, user._id);
});
```

```
// when we need the information for the user, the deserializeUser function is called with the id that we previously serialized to fetch the user from the database
passport.deserializeUser((id, done) => {
  User.findById(id)
    .then(dbUser => {
      done(null, dbUser);
    })
    .catch(err => {
      done(err);
    });
});
```

```
passport.use(
  new LocalStrategy((username, password, done) => {
    User.findOne({ username: username })
      .then(found => {
        if (found === null) {
          done(null, false, { message: 'Wrong credentials' });
        } else if (!bcrypt.compareSync(password, found.password)) {
          done(null, false, { message: 'Wrong credentials' });
        } else {
          done(null, found);
        }
      })
      .catch(err => {
        done(err, false);
      });
  })
);
```

Now we add the login post route and use passport there

```
// routes/auth.js
const passport = require('passport');
```

```
router.post(
  '/login',
  passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/auth/login',
    failureFlash: true,
    passReqToCallback: true
  })
);
```

In passport the user is not in req.session but in the request obj directly 
So the loginCheck middleware can be changed to 

```
// routes/index.js
const loginCheck = () => {
  return (req, res, next) => {
    // if (req.user)
    if (req.isAuthenticated()) {
      // if user is logged in, proceed to the next function
      next();
    } else {
      // else if user is not logged in, redirect to /login
      res.redirect('/auth/login');
    }
  };
};
```

And we can also give the user to the index view - change the index view to:

```
router.get('/', (req, res, next) => {
  // passport
  const user = req.user;
  console.log('req.user: ', req.user);
  res.render('index', { user: user });
});
```

If we want to log in the user we can use req.login() or req.logout()

```
// routes/auth.js
In the post signup route:

      User.create({ username: username, password: hash })
        .then(dbUser => {
          // passport - login the user

          req.login(dbUser, err => {
             if (err) next(err);
             else res.redirect('/');
           });

        })
```

```
And the logout :
// routes/auth.js

router.get('/logout', (req, res, next) => {
  // passport
  req.logout();
  res.redirect('/');
});
```
For the error messages :

```
$ npm install connect-flash
```
```
// app.js
const flash = require('connect-flash');
app.use(flash());
```
Now the login route where we want to show the flash message:

```
// routes/auth.js
router.get('/login', (req, res) => {
  res.render('auth/login', { errorMessage: req.flash('error') });
});
```

*****************************************************************************

# Add Github Login

OAuth for social login - a way to access external websites without creating a user account on it
You are using your social network to authenticate on other websites

https://github.com/jaredhanson/passport-github

Register app in github 

You need 

Github id

Github secret

```
$ npm install passport-github
```

Add a field for the GitHub ID to the user model
```
// models/User.js
const userSchema = new Schema({
  username: String,
  password: String,
  githubId: String
});
```

```
// app.js
const GithubStrategy = require('passport-github').Strategy;

passport.use(
  new GithubStrategy(
    {
      clientID: process.env.GITHUB_ID,
      clientSecret: process.env.GITHUB_SECRET,
      callbackURL: 'http://127.0.0.1:3000/auth/github/callback'
    },
    (accessToken, refreshToken, profile, done) => {
      // find a user with profile.id as githubId or create one
      User.findOne({ githubId: profile.id })
        .then(found => {
          if (found !== null) {
            // user with that githubId already exists
            done(null, found);
          } else {
            // no user with that githubId
            return User.create({ githubId: profile.id }).then(dbUser => {
              done(null, dbUser);
            });
          }
        })
        .catch(err => {
          done(err);
        });
    }
  )
);
```

```
// views/auth/login.hbs
<a href="/auth/github">Login via Github</a>
```

We need to have these routes

```
// routes/auth.js
router.get('/github', passport.authenticate('github'));

router.get(
  '/github/callback',
  passport.authenticate('github', {
    successRedirect: '/',
    failureRedirect: '/auth/login'
  })
);
```