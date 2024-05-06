import { NextFunction, Request, RequestHandler, Response } from "express";
import jwt from "jsonwebtoken";
import { handleSuccess, handleError } from "../service/handleReply";
import createError from "http-errors";
import User from "../models/user.model";


declare global {
  namespace Express {
    interface Request {
      user?: any; // 在這裡定義 user 的類型
      token?: string; // 在這裡定義 token 的類型
    }
  }
}

let jwtFn: any = {
  // generating token
  async jwtGenerator(userInfo: any, res: any, next: NextFunction) {
    try {
      await User.findByIdAndUpdate(userInfo["_id"], {token : ""}, {new : true});
      let jwtToken = jwt.sign({id : userInfo["_id"].toString()}, process.env.JWT_SECRET, {expiresIn : process.env.JWT_DAYS});
      
      // login
      await User.findByIdAndUpdate(userInfo["_id"], {token : jwtToken.toString()}, {new : true});
      handleSuccess(res, { accessToken: jwtToken }, "Login successfully");
    } catch (err) {
      await User.findByIdAndUpdate(userInfo["_id"], {token : ""}, {new : true});
      return next(err);
    }
  },

  // verify token
  async isAuth(req: Request, res: Response, next: NextFunction) {
    try {
      console.log(req.headers.authorization);
      let token: string = "";
      if (req.headers.authorization && req.headers.authorization.startsWith("Bearer")) {
        console.log("111111");
        token = req.headers.authorization.split(" ")[1];
      };
      if (!token) {
        console.log("2222222");
        return handleError(res, createError(400, "Please login first"));
      };
      let decodedPayload: any = await new Promise((resolve, reject) => {
        jwt.verify(token, process.env.JWT_SECRET, (err, payload) => {
          if (err) {
            console.log("3333333");
            return reject(err);
          } else {
            console.log("4444444");
            resolve(payload);
          }
        })
      });


      console.log(decodedPayload.id);

      // login
      const user = await User.findOne({ "_id" : decodedPayload.id}).select("token");
      console.log('user:', user);
      if(!user){
          console.log("5555555");
          return handleError(res, createError(400, "Please login."));
      }
      if(!user.token || user.token != token){
          console.log("6666666");
          return handleError(res, createError(400, "Please login."));
      }

      const currentUser = await User.findById(decodedPayload.id).select('token role');
      console.log('currentUser:', currentUser);
      if (!currentUser) {
        return handleError(res, createError(401, "User not found"));
      }
      req.user = currentUser;
      req.token = token;
      next();
    } catch (err) {
      return handleError(res, createError(401, "Unauthorized"));
    }
  }
}

export default jwtFn;
