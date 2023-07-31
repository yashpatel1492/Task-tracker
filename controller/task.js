import { Task } from "../models/task.js"
export const addTask = async(req,res,next)=>{
    try {
        const{title, description} = req.body
    const task = await Task.create({
        title,
        description,
        user:req.user
    })
    res.status(200).json({
        success:true,
        message:`Task created success fully by ${req.user.name}`
    })   
    } catch (error) {
        next(new Error(error))
    }
    
}
export const myTask = async(req,res,next)=>{
    try {
        const task = await Task.find({user:req.user})
    if(!task){
        res.status(200).json({
            success:true,
            message:"There is no task assigned yet"
        })
    }
    res.status(200).json({
        success:true,
        task
    }) 
    } catch (error) {
        next(new Error(error))
    }
      
}
export const updateTask = async(req,res,next)=>{
    try {
        const task = await Task.findById(req.params.id)
    if(!task) return next(new Error("There is no such task id"))
    task.isCompleted = !task.isCompleted
    await task.save()
    res.status(200).json({
        success:true,
        message:"Task updated successfully",
        task
    })
    } catch (error) {
        next(new Error(error))
    }
       
}
export const deleteTask = async(req,res,next)=>{
    try {
        const task = await Task.findById(req.params.id)
    if(!task) return next(new Error("There is no such task id"))
    task.deleteOne({_id:req.params.id})
    res.status(200).json({
        success:true,
        message:"Task deleted successfully",
        
    })   
    } catch (error) {
        next(new Error(error))
    }
    
}
