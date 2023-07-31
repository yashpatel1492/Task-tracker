import mongoose from "mongoose";
export const connectDb=()=>{
    // console.log(process.env.MONGO_URL)
    mongoose.connect(process.env.MONGO_URL).then(()=>{
    console.log("Connected database successfully")
})
}
