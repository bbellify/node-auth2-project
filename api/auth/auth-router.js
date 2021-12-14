const bcrypt = require('bcryptjs')
const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { tokenBuilder } = require('../auth/auth-helpers')

const User = require('../users/users-model')


router.post("/register", validateRoleName, (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
  let user = {
    username: req.body.username,
    password: req.body.password,
    role_name: req.role_name
  }
  
  const hash = bcrypt.hashSync(user.password, 8)
  user.password = hash

  User.add(user)
    .then(newUser => {
      res.status(201).json({
        user_id: newUser.user_id,
        username: newUser.username,
        role_name: newUser.role_name
      })
    })
    .catch(next)



});


router.post("/login", checkUsernameExists, (req, res, next) => {

  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
  const { password } = req.body
  if (bcrypt.compareSync(password, req.user.password)) {
    const token = tokenBuilder(req.user)
    
    res.status(200).json({
      message: `${req.user.username} is back!`,
      token
    })
  } else {
    next({ status: 401, message: 'Invalid credentials'})
  }
});

module.exports = router;
