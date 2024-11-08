async function auth(request, reply) {
  // Kiểm tra xem có token không
  if (request.cookies && request.cookies.token) {
    try {
      // Xác thực token
      const user = await request.server.jwt.verify(request.cookies.token);
      request.user = user;
      request.log.info(user);
    } catch (error) {
      // Nếu token không hợp lệ, kiểm tra refreshToken
      const currentUrl = request.url;
      console.log("Giá trị của currentUrl:", currentUrl);
      if (request.cookies.refreshToken) {
        console.log("Giá trị của refreshToken:", request.cookies.refreshToken);
        try {
          const user = await request.server.jwt.verify(
            request.cookies.refreshToken,
            { ignoreExpiration: true }
          );
          request.user = user;
          request.log.info(user);

          // Lấy thông tin người dùng từ MongoDB
          const storedUser = await request.server.mongo.db
            .collection("users")
            .findOne({ username: user.username });
          console.log("Giá trị của storedUser:", storedUser);
          console.log(
            "Giá trị của storedUser.refreshToken:",
            storedUser.refreshToken
          );
          console.log(
            "Giá trị của cookie.refreshToken:",
            request.cookies.refreshToken
          );
          // Kiểm tra nếu refresh token hợp lệ
          if (
            storedUser &&
            storedUser.refreshToken === request.cookies.refreshToken
          ) {
            console.log("Giá trị của refreshToken:", storedUser);

            // Tạo Access Token mới
            const newToken = request.server.jwt.sign(
              { username: user.username, role: user.role },
              { expiresIn: "1m" }
            );
            console.log("Giá trị của user.username:", user.username);
            console.log("Giá trị của user.role:", user.role);

            // Tạo Refresh Token mới
            const newRefreshToken = request.server.jwt.sign(
              { username: user.username, role: user.role },
              { expiresIn: "7d" }
            );

            // Cập nhật Refresh Token trong MongoDB
            await request.server.mongo.db
              .collection("users")
              .updateOne(
                { username: user.username },
                { $set: { refreshToken: newRefreshToken } }
              );

            // Gửi Access Token và Refresh Token mới về client
            reply.setCookie("token", newToken, { httpOnly: true });
            console.log("Giá trị của newToken:", newToken);
            reply.setCookie("refreshToken", newRefreshToken, {
              httpOnly: true,
            });
            console.log("Giá trị của newRefreshToken:", newRefreshToken);

            // Lưu thông tin người dùng vào request
            request.user = { username: user.username, role: user.role };
            console.log("Giá trị của currentUrl:", currentUrl);
            // return reply.redirect(currentUrl);
          } else {
            reply.clearCookie("token");
            reply.clearCookie("refreshToken");
            return reply.render("login", {
              errMessage: "Invalid refresh token",
            });
          }
        } catch (err) {
          reply.clearCookie("token");
          reply.clearCookie("refreshToken");
          return reply.render("login", { errMessage: "Token hết hạn" });
        }
      } else {
        return reply.render("login", {
          errMessage: "Chưa cung cấp refresh token",
        });
      }
    }
  } else {
    return reply.render("login", { errMessage: "Chưa đăng nhập" });
  }
}

module.exports = auth;
