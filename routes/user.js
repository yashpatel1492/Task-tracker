import express from 'express'
import { getUserDetails, register,login,logout } from '../controller/user.js'
import { isAuthenticated } from '../middleware/auth.js'
const router = express.Router()

router.post('/new',register)
router.post('/login',login)
//dynamic route
//use only in last
router.get('/me',isAuthenticated,getUserDetails)
router.get('/logout',logout)
export default router