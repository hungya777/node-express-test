import mongoose from "mongoose";
import validator from "validator";

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, "請輸入姓名"],
  },
  email: {
    type: String,
    required: [true, "請輸入電子郵件"],
    unique: true,
    lowercase: true,
    // 自訂驗證, 使用 validator 套件
    validate: {
      validator(value: string) {
        return validator.isEmail(value);
      },
      message: "請輸入正確的電子郵件格式",
    },
  },
  role: {
    type: String,
    enum: ["user", "admin"],
    default: "user",
  },
  password: {
    type: String,
    required: [true, "請輸入密碼"],
    minlength: [8, "密碼至少要 8 個字元"],
  },
  birthday: {
    type: Date,
    required: [true, "請輸入生日"],
  },
  token : {
    type : String,
    default : "",
    select : false
  },
  createdAt : {
    type : Date,
    default : Date.now,
    select : false
  },
  updatedAt : {
      type : Date,
      default : Date.now,
      select : false
  }
},{
  versionKey : false
});

const User = mongoose.model("User", userSchema);

export default User;