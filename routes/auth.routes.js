const {Router} = require('express')
const bcrypt  = require('bcryptjs')
const {check, validationResult} = require('express-validator')
const User = require('../models/User')
const router = Router()
const config = require('config')
const jwt = require('jsonwebtoken')

// /api/auth/register
router.post(
    '/register',
    [
        check('email', 'This is not a valid email').isEmail(),
        check('password', 'The password min length is 6 chars').isLength({min: 6})

    ],
    async (req, res) => {
    try {
        console.log("Body:", req.body)
        const errors = validationResult(req)

        if (!errors.isEmpty()){
            return res.status(400).json({
                errors: errors.array(),
                message: 'There is an error occured during processing your data. Please check the data provided'
            })

        }

        const {email, password} = req.body

        const candidate = await User.findOne({email})

        if (candidate) {
          return res.status(400).json({message: 'This user is registered. Please login to your account'})
      }

      const hashedPassword = await bcrypt.hash(password, 12)
      const user = new User({email, password: hashedPassword})

      await user.save()

      res.status(201).json({message: 'The user was created'})

    } catch (e) {
        res.status(500).json({message: 'Something went wrong. Try it again.'})
    }

})

// /api/auth/login
router.post('/login',

[
    check('email', 'Please type a valid email address').normalizeEmail().isEmail(),
    check('password', 'Please enter the password').exists()

],
async (req, res) => {
try {

    const errors = validationResult(req)

    if (!errors.isEmpty()){
        return res.status(400).json({
            errors: errors.array(),
            message: 'There is an error occured during login. Please check your credentials'
        })

    }

    const {email, password} = req.body

    const user = User.findOne({email})

    if (!user) {
        return res.status(400).json({message: 'User was not found'})
    }

    const isMatch = await bcrypt.compare(password, user.password)

    if(!isMatch) {
        return res.status(400).json({message: 'The password you provided does not match with our records'})
    }

    const token = jwt.sign(
        {userId: user.id},
        config.get('jwtSecret'),
        {expiresIn: '1h'}
        )

        res.json({token, userId: userId})
    
} catch (e) {
    res.status(500).json({message: 'Something went wrong. Try it again.'})
}

})


module.exports = router