import { User } from "../models/user.js"
import jwt from "jsonwebtoken"
export const isAuthenticated = async(req,res,next)=>{
    try {
        const {token} = req.cookies
    // console.log(token)
    if(!token){
        return res.status(404).json({
            success:false,
            message:"Please login first"
        })
    }
    const decoded = jwt.verify(token,process.env.JWTTOKEN)
    req.user = await User.findById(decoded)
    next()
    } catch (error) {
        next(new Error(error))
    }
    
}