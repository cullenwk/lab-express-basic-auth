const router = require("express").Router();
const UserModel = require('../models/User.model')
var bcrypt = require('bcryptjs');
const { response } = require("../app");

// Handles GET requests to /signin and shows a form
router.get('/signin', (req, res, next) => {
    res.render('auth/signin.hbs')
})

// Handles GET requests to /signup and shows a form
router.get('/signup', (req, res, next) => {
    res.render('auth/signup.hbs')
  })

// Handles POST requests to /signup 

router.post('/signup', (req, res, next) => {
    const {username, password} = req.body
    console.log(username, password)

   if (username == ''|| password == ''){
       // throw error
       res.render('auth/signup.hbs', {error: 'Please enter all fields'})
       return;
   }

   // validate if the password is strong
   /*let passRegEx = /'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$'/
   if (!passRegEx.test(password)) {
    res.render('auth/signup.hbs', {error: 'Please enter Minimum eight characters, at least one letter and one number for your password'})
    return;
  }*/

   
   // encryption
    let salt = bcrypt.genSaltSync(10);
    let hash = bcrypt.hashSync(password, salt);

    console.log(salt)
    console.log(hash)

    UserModel.create({username, password: hash})
    .then(() => {
        res.redirect('/')
    })
    .catch((err) => {
        next (err)
    })
}) 

// Handles POST requests to /signin 
router.post('/signin', (req, res, next) => {
    const {username, password} = req.body

    // do the validation first

    //find the user email
    UserModel.find({username})
      .then((usernameResponse) => {
          //if the email exist check the password 
          if (usernameResponse.length) {
                //bcrypt decryption 
                let userObj = usernameResponse[0]

                let isMatching = bcrypt.compareSync(password, userObj.password);
                if (isMatching) {
                    
                    req.session.myProperty = userObj
                    //req.session.welcome = 'Helllo'

                     res.redirect('/private')
            }
            else {
              res.render('auth/signin.hbs', {error: 'Password not matching'})
              return;
            }
          }
          else {
            res.render('auth/signin.hbs', {error: 'Username does not exist'})
            return;
          }
      })
      .catch((err) => {
        next(err)
      })     
})

// Our Custom middleware that checks if the user is loggedin
const checkLogIn = (req, res, next) => {
    if (req.session.myProperty ) {
      //invokes the next available function
      next()
    }
    else {
      res.redirect('/main')
    }
}

router.get('/private', checkLogIn, (req, res, next) => {
    let myUserInfo = req.session.myProperty  
    res.render('auth/private.hbs', {name: myUserInfo.username})
})


router.get('/main', (req, res, next) => {
    let myUserInfo = req.session.myProperty  
    res.render('auth/main.hbs')
})




module.exports = router