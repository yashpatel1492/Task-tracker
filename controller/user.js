import { User } from "../models/user.js"
import bcrypt from 'bcrypt'
import { sendCookie } from "../utils/features.js"
import jwt from "jsonwebtoken"
export const register = async(req,res,next)=>{
    const {token} = req.cookies
    if(!token){
    try {
        const {name,email,pasword} = req.body
    let user = await User.findOne({email:email})
    if(user!=null) return next( new Error("User already exist"))
    const encryptedpass = await bcrypt.hash(pasword,10)
    user = await User.create({
        name:name,
        email:email,
        pasword:encryptedpass
    })
    sendCookie(res,user,"User created successfully")
    } catch (error) {
        next(new Error(error))
    }
}
else{
    const decoded = jwt.verify(token,process.env.JWTTOKEN)
    req.user = await User.findById(decoded)
    return res.status(404).json({
        success:false,
        message:`You already logged in as ${req.user.name}`
    })
}
    
}
export const login = async (req,res,next)=>{
    const {token} = req.cookies
    if(!token){
    try {
        const {email,pasword} = req.body
    const user = await User.findOne({email:email}).select("+pasword")
    if(user===null) return next(new Error("User not exists"))
    // console.log(user.email)
    const ismatched = await bcrypt.compare(pasword,user.pasword)
    if(!ismatched){
        return res.status(404).json({
            success:false,
            message:"pasword mismatched"
        })
    }
    sendCookie(res,user,`Welcome back ${user.name}`)
    } catch (error) {
        next(new Error(error))
    }
}
else{
    const decoded = jwt.verify(token,process.env.JWTTOKEN)
    req.user = await User.findById(decoded)
    return res.status(404).json({
        success:false,
        message:`You already logged in as ${req.user.name}`
    })
}
}
export const getUserDetails = async(req,res,next)=>{
    try {
        res.json({
            success:true,
            user:req.user
        })
    } catch (error) {
        next(new Error(error))
    }    
    
}
export const logout = async(req,res,next)=>{
    try {
        res.status(200).cookie("token","",{
            httpOnly:true,
            expires: new Date(Date.now()),
            sameSite:"none",
            secure:true
        }).json({
            success:true,
            message:"Logged out successfully"
        })
    } catch (error) {
        next(new Error(error))
    }
    
}