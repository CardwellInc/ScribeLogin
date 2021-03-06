if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config()
  }
  
  const express = require('express')
  const app = express()
  const bcrypt = require('bcrypt')
  const passport = require('passport')
  const flash = require('express-flash')
  const session = require('cookie-session')
  const methodOverride = require('method-override')

  require('./models/db');


  const users = require('./models/user');
  
  const initializePassport = require('./passport-config')
  initializePassport(
    passport,
    username => users.find(user => user.username === username),
    id => users.find(user => user.id === id)
  )
  
  const AddingName = require('./models/CMWC');
  
  app.set('view-engine', 'ejs')
  app.use(express.urlencoded({ extended: false }))
  app.use(flash())
  app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
  }))
  app.use(passport.initialize())
  app.use(passport.session())
  app.use(methodOverride('_method'))
  
  app.get('/', checkAuthenticated, (req, res) => {
    res.render('index.ejs', { name: req.user.name, cmwcode: req.user.cmwcode })
  })
  
  app.get('/login', checkNotAuthenticated, (req, res) => {
    res.render('login.ejs')
  })

  app.get('/Meep', checkAuthenticated, (req, res) => {
    res.render('Meep.ejs')
  })
  
  app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
  }))
  
  app.get('/CMWCardwell', checkNotAuthenticated, (req, res) => {
    res.render('register.ejs')
  })
  
  app.post('/CMWCardwell', checkNotAuthenticated, async (req, res) => {
    try {
      const hashedPassword = await bcrypt.hash(req.body.password, 10)
      AddingName.push({
        id: Date.now().toString(),
        name: req.body.name,
        username: req.body.username,
        password: hashedPassword
      })
      res.redirect('/login')
      console.log(AddingName)
    } catch {
      res.redirect('/CMWCardwell')
    }
  })
  
  app.delete('/logout', (req, res) => {
    req.logOut()
    res.redirect('/login')
  })
  
  function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
      return next()
    }
  
    res.redirect('/login')
  }
  
  function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
      return res.redirect('/')
    }
    next()
  }
 
  const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Our app is running on port ${ PORT }`);
});