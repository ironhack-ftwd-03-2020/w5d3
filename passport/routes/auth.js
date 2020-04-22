const express = require('express');
const bcrypt = require('bcrypt');

// require passport
const passport = require('passport');

const router = express.Router();
const User = require('../models/User');

router.get('/signup', (req, res) => {
  res.render('auth/signup');
});

router.get('/login', (req, res) => {
  res.render('auth/login', { errorMessage: req.flash('error') });
});

router.post(
  '/login',
  passport.authenticate('local', {
    // here you can add your own routes 
    successRedirect: '/',
    failureRedirect: '/auth/login',
    // this is set
    failureFlash: true,
    passReqToCallback: true
  })
);



router.post('/signup', (req, res, next) => {
  const { username, password } = req.body;

  if (password.length < 8) {
    res.render('auth/signup', {
      message: 'Your password must be 8 characters minimun.'
    });
    return;
  }
  if (username === '') {
    res.render('auth/signup', { message: 'Your username cannot be empty' });
    return;
  }

  User.findOne({ username: username }).then(found => {
    if (found !== null) {
      res.render('auth/signup', { message: 'This username is already taken' });
    } else {
      const salt = bcrypt.genSaltSync();
      const hash = bcrypt.hashSync(password, salt);

      User.create({ username: username, password: hash })
        .then(dbUser => {

          // res.redirect('login');
          req.login(dbUser, err => {
            if (err) {
              next(err);
            } else {
              res.redirect('/');
            }
          })
        })
        .catch(err => {
          next(err);
        });
    }
  });
});

router.get('/logout', (req, res, next) => {
  // passport syntax - this is called 'syntax sugar' around the basci syntax:
  // req.session.destroy
  req.logout();
  res.redirect('/');
});

module.exports = router;
