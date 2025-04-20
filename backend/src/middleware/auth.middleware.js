import jwt from "jsonwebtoken"
import User from "../models/user.model.js"

export const protectRoute = async(req, res, next)=>{
    try{
        const token = req.cookies.jwt
        // console.log("🔐 Token:", req.cookies.jwt);

        if(!token){
            return res.status(401).json({message:"Unauthorized access ❌"})
        }

        const decoded = jwt.verify(token, process.env.JWT_KEY)

        if(!decoded){
            return res.status(401).json({message:"Unauthorized access ❌ token is invalid"})
        }

        const user = await User.findById(decoded.userId).select("-password")

        if(!user){
            return res.status(404).json({message:"User not found ❌"})
        }

        req.user = user
        next()
    }
    catch(error){
        console.log("error in verifying token: ",error)
        return res.status(500).json({message:"internal error ❌"})
    }
}