const router = require('express').Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const secrets = require('../config/secrets.js');

const Users = require('../users/users-model.js');

//
// when we register, all we do is take the username
// and password, hash the password (with salt, of course!),
// and store them in the DB, and return success.
//
// these will be used in any /login request to validate
// the login attempt.
//
router.post('/register', (req, res) => {
  let user = req.body;
  const hash = bcrypt.hashSync(user.password, 10); // 2 ^ n
  user.password = hash;

  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});


//
// when a /login occurs, the browser app must pass the username
// and password in the body.
//
// here, we validate the password guess against the database.
//
// if the login attempt is successful, we generate a JWT and
// send it back to the browser. 
//
// The browser app will save the token, and should know to send 
// it in an Authorization header in any future API calls to 
// "restricted" API endpoints (where authentication is required).
//
// This prevents the user from having to enter their credentials
// every time an API call is made, and prevents the browser app
// from needing to cache the username/password so it can send it
// in headers every time an API call is made. The browser app just
// sends the token instead.
//
// username/password is long-lasting... if they ever get out,
// they can be exploited for a long time without being detected.
//
// but JWT's have a much shorter lifespan... they are set to expire.
// So they are much more secure for the browser app to use.
//
// remember that the JWT consists of a header, a payload, and a
// signature. The header describes how the signature was generated.
// The payload contains information that the API server/service
// (or other related services) might need to do its job. Typically,
// the payload consists of "claims" about the "subject" - properties,
// permissions, etc.
//
// Because the JWT is *not encrypted*, NEVER store anything sensitive 
// in a JWT!!! It is essentially plain text (though encoded ... but the
// encoding is not secure at all!)
router.post('/login', (req, res) => {
  // get the username and password from the body.
  let { username, password } = req.body;


  Users.findBy({ username })
    .first()
    .then(user => {

      if (user && bcrypt.compareSync(password, user.password)) {


        const token = genToken(user);
        console.log('token : ', token);

        res.status(200).json({
          message: `Welcome ${user.username}!`,
          token
        });

      } else {

        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    // this is for DB lookup errors...
    .catch(error => {
      res.status(500).json(error);
    });
});


function genToken(user) {


  const payload = {
    subject: "user",
    username: user.username
  };

  const secret = secrets.jwtSecret;


  const options = {
    expiresIn: '1h'
  };

  //
  // finally, just sign the dang thing and return it already!
  //
  return jwt.sign(payload, secret, options);

}

module.exports = router;
