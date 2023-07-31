import mongoose from "mongoose";
const taskschema = new mongoose.Schema({
    title:{
        type:String,
        required:true,
    },
    description:{
        type:String,
        required:true,
    },
    isCompleted:{
        type:Boolean,
        default:false
    },
    user:{
        type:mongoose.Schema.Types.ObjectId,
        ref:"users",
        required:true
    },
    createdAt:{
        type:Date,
        default: new Date(Date.now())
    }
})
const Task = mongoose.model('task',taskschema);
export {Task}