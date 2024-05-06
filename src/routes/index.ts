import { Router, Request, Response } from "express";
const router = Router();

/* GET home page. */
router.get("/", (req: Request, res: Response) => {
  res.send("index route");
});

export default router;