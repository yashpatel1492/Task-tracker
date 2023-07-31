import jwt from 'jsonwebtoken';
export const sendCookie = (res,user,message) => {
    const token = jwt.sign({_id:user._id},process.env.JWTTOKEN)
    res.status(201).cookie("token",token,{
        httpOnly:true,
        sameSite:"none",
        secure:true
    }).json({
        success:true,
        message:message
    })
}