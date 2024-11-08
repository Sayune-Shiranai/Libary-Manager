function authority(role) {
  return (request, reply, done) => {
    if (request.user && request.user.role && request.user.role === role) {
      done();
    } else {
      reply.render("login", {
        errMessage: `Bạn cần phải đăng nhập với quyền ${requiredRole} để truy cập trang này.`,
      });
    }
  };
}

module.exports = authority;
