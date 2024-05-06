import { Router } from "express";
import userController from "../controllers/user.controller";
import { handleErrorAsync } from "../service/handleErrorAsync";
import jwtFn from "../middleware/auth";

const router = Router();

// register
router.post("/register", handleErrorAsync(userController.signUp));

// login
router.post("/login", handleErrorAsync(userController.login));

// logout
router.post("/logout", jwtFn.isAuth, handleErrorAsync(userController.logout));

// get users
router.get("/users", handleErrorAsync(userController.getUsers));

export default router;