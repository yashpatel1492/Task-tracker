import express from 'express'
import { isAuthenticated } from '../middleware/auth.js'
import { addTask,myTask, updateTask,deleteTask} from '../controller/task.js'
const router = express.Router()
router.post('/new',isAuthenticated,addTask)
router.get('/mytask',isAuthenticated,myTask)
router.route('/:id').put(isAuthenticated,updateTask).delete(isAuthenticated,deleteTask)
export default router