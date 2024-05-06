import { Response } from "express";

/* reply format:
{
  ok: boolean,  // true: success, false: error
  msg: string, // supplementary message
  data: string | array | object  // reply data depends on the request
}
*/

const handleSuccess = (
  res: Response,
  data: String | Array<any> | Object,
  message: string = "success"
) => {
  res
    .send({
      status: true,
      message: message,
      data,
    })
    .end();
};

const handleError = (res: Response, err?: Error) => {
  let message = "error";
  if (err) {
    message = err.message;
  }

  res
    .status(400)
    .send({
      status: false,
      message: message,
    })
    .end();
};

const handle401Error = (res: Response, message: string = "Unauthorized") => {
  res
    .status(401)
    .send({
      status: false,
      message: message,
    })
    .end();
};

const handle403Error = (res: Response, message: string = "Forbidden") => {
  res
    .status(403)
    .send({
      status: false,
      message: message,
    })
    .end();
}

export { handleSuccess, handleError, handle401Error, handle403Error };