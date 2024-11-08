const path = require("node:path");
const fs = require("node:fs");
const util = require("node:util");
const { pipeline } = require("node:stream");
const pump = util.promisify(pipeline);
const { createHmac, randomBytes } = require("node:crypto");
const { ObjectId } = require("@fastify/mongodb");

const fastifyApp = require("fastify")({ logger: true });

fastifyApp.register(require("@fastify/mongodb"), {
  forceClose: true,
  url: "mongodb://127.0.0.1:27017/QL_upload_truyen_db",
});

fastifyApp.register(require("@fastify/formbody"));

fastifyApp.register(require("@fastify/multipart"), {
  attachFieldsToBody: true,
});

fastifyApp.register(require("@fastify/view"), {
  engine: {
    pug: require("pug"),
  },
  root: "views",
  propertyName: "render",
});

fastifyApp.register(require("@fastify/static"), {
  root: path.join(__dirname, "public"),
  prefix: "/public/",
});

fastifyApp.register(require("@fastify/jwt"), {
  secret: "sayune",
});

fastifyApp.register(require("@fastify/cookie"), {
  secret: "sayuneshiranai",
  hook: "onRequest",
});

const auth = require("./auth");
const authority = require("./authority");

// Declare a route
fastifyApp.get("/", function handler(request, reply) {
  reply.send({ hello: "world" });
});

// route(get/admin/list-user): return user list user
fastifyApp.get(
  "/admin/list-user",
  { onRequest: [auth, authority("admin")] },
  async function (req, rep) {
    req.log.info(req.user);
    // read users from studentdb
    const users = await this.mongo.db
      .collection("users")
      .find({}, { projection: { password: 0 } })
      .toArray();

    rep.render("admin", { users });

    return rep;
  }
);

//router(get/admin/create-admin): create a new admin
fastifyApp.get(
  "/admin/create-admin",
  { onRequest: [auth, authority("admin")] },
  function (req, rep) {
    rep.render("create-admin");
  }
);

// router (post/admin/create-admin): create a new admin
fastifyApp.post("/admin/create-admin", async function (req, rep) {
  //  verify.request.body
  if (req.body.password === req.body.confirm) {
    const salt = randomBytes(16).toString("hex");
    const hpass = createHmac("sha256", salt)
      .update(req.body.password)
      .digest("hex");

    // save req.body --> mongodb studentdb
    const result = await this.mongo.db.collection("users").insertOne({
      fullname: req.body.fullname,
      username: req.body.username,
      role: req.body.role,
      salt,
      hpass,
      createdDate: Date.now(),
    });

    rep.redirect("/admin/list-user");
  } else {
    //Error
    rep.send(new Error("Bad request"));
  }
});

// router(get/admin/list-user/update/:id): update user
fastifyApp.get("/admin/list-user/update/:id", async function (req, rep) {
  const user = await this.mongo.db
    .collection("users")
    .findOne({ _id: new ObjectId(req.params.id) });
  rep.render("update-user", { user });

  return rep;
});

// router(get/admin/list-user/update/:id): update user
fastifyApp.post("/admin/list-user/update/:id", async function (req, rep) {
  const result = await this.mongo.db.collection("users").updateOne(
    { _id: new ObjectId(req.params.id) },
    {
      $set: {
        fullname: req.body.fullname,
        username: req.body.username,
        role: req.body.role,
      },
    }
  );

  rep.redirect("/admin/list-user");
});

//router(get/admin/list-user/delete/:id): delete a user
fastifyApp.get("/admin/list-user/delete/:id", async function (req, rep) {
  const result = await this.mongo.db
    .collection("users")
    .deleteOne({ _id: new ObjectId(req.params.id) });

  rep.redirect("/admin/list-user");
});

fastifyApp.get("/sign-up", function (req, rep) {
  rep.render("create-user");
});

//router(post/sign-up): create a new user
fastifyApp.post("/sign-up", async function (req, rep) {
  if (req.body.password === req.body.confirm) {
    const salt = randomBytes(16).toString("hex");
    const hpass = createHmac("sha256", salt)
      .update(req.body.password)
      .digest("hex");

    // save req.body --> mongodb studentdb
    const result = await this.mongo.db.collection("users").insertOne({
      fullname: req.body.fullname,
      username: req.body.username,
      role: req.body.role,
      salt,
      hpass,
      createdDate: Date.now(),
    });

    rep.redirect("/sign-in");
  } else {
    //Error
    rep.send(new Error("Bad request"));
  }
});

//router(get/sign-in): login
fastifyApp.get("/sign-in", function (req, rep) {
  rep.render("login");
});

//router(post/sign-in): login
fastifyApp.post("/sign-in", async function (req, rep) {
  const action = req.body.action;

  if (action === "Login") {
    if (req.body.username && req.body.password) {
      const user = await this.mongo.db
        .collection("users")
        .findOne({ username: req.body.username });
      if (user) {
        const hpass = createHmac("sha256", user.salt)
          .update(req.body.password)
          .digest("hex");
        if (hpass === user.hpass) {
          // Login thành công
          const token = this.jwt.sign(
            { username: user.username, role: user.role },
            { expiresIn: "1m" }
          );

          const refreshToken = this.jwt.sign(
            { username: user.username, role: user.role },
            { expiresIn: "7d" }
          );

          await this.mongo.db
            .collection("users")
            .updateOne({ username: user.username }, { $set: { refreshToken } });

          rep.cookie("token", token, { httpOnly: true });
          rep.cookie("refreshToken", refreshToken, { httpOnly: true });
          if (user.role === "admin") {
            rep.redirect("/admin/list-user");
          } else if (user.role === "user") {
            rep.redirect("/home");
          } else {
            rep.render("login", { errMessage: "Lỗi role" });
          }
        } else {
          rep.render("login", { errMessage: "Sai mật khẩu" });
        }
      } else {
        rep.render("login", {
          errMessage: `${req.body.username} không tồn tại`,
        });
      }
    } else {
      rep.render("login", { errMessage: "Bạn phải nhập username và password" });
    }
  } else if (action === "Register") {
    return rep.redirect("/sign-up");
  } else {
    rep.send(new Error("Bad request"));
  }
  return rep;
});

//router(post/logout): logout
fastifyApp.post("/logout", { onRequest: auth }, async function (req, rep) {
  const user = req.user;
  req.log.info(req.user);

  if (user) {
    rep.clearCookie("token", { path: "/" });
    rep.clearCookie("refreshToken", { path: "/" });

    await this.mongo.db
      .collection("users")
      .updateOne({ username: user.username }, { $unset: { refreshToken: "" } });
    rep.redirect("/sign-in");
  } else {
    rep.send(new Error("Logout failed"));
  }
  return rep;
});

//route(get/admin/libary-manager): return item list
fastifyApp.get(
  "/admin/libary-manager",
  { onRequest: [auth, authority("admin")] },
  async function (req, rep) {
    // read users from studentdb
    const libary = await this.mongo.db.collection("libary").find({}).toArray();

    rep.render("libary-manager", { libary });

    return rep;
  }
);

function removeAccents(str) {
  return str
    .normalize("NFD") // Tách các ký tự có dấu thành tổ hợp ký tự không dấu + dấu
    .replace(/[\u0300-\u036f]/g, ""); // Loại bỏ dấu
}

function createSlug(itemname) {
  return removeAccents(itemname)
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, "") // Loại bỏ các ký tự đặc biệt
    .trim()
    .replace(/\s+/g, "-"); // Thay khoảng trắng bằng dấu gạch ngang
}

//router(get/admin/create-item): create item form
fastifyApp.get(
  "/admin/create-item",
  { onRequest: [auth, authority("admin")] },
  function handler(req, rep) {
    rep.render("create-item");
  }
);

//router(post/admin/create-item): create a new item
fastifyApp.post("/admin/create-item", async function (req, rep) {
  try {
    await pump(
      req.body.imgavt.toBuffer(),
      fs.createWriteStream(
        path.join(__dirname, "public/avt-item", req.body.imgavt.filename)
      )
    );
    // save req.body --> mongodb studentdb
    const slug = createSlug(req.body.itemname.value);
    const result = await this.mongo.db.collection("libary").insertOne({
      itemname: req.body.itemname.value,
      slug: slug,
      theloai: req.body.theloai.value,
      tacgia: req.body.tacgia.value,
      noidung: req.body.noidung.value,
      imgavt: req.body.imgavt.filename,
      createdDate: Date.now(),
    });

    rep.redirect("/admin/libary-manager");
  } catch (err) {
    rep.send(err);
  }
});

//router(get/admin/libary-manager/update/:id): update item
fastifyApp.get("/admin/libary-manager/update/:id", async function (req, rep) {
  const item = await this.mongo.db
    .collection("libary")
    .findOne({ _id: new ObjectId(req.params.id) });
  rep.render("update-item", { item });

  return rep;
});

//router(post/admin/libary-manager/:id): update item
fastifyApp.post("/admin/libary-manager/update/:id", async function (req, rep) {
  try {
    let imgavt;

    if (req.body.imgavt && req.body.imgavt.filename) {
      await pump(
        req.body.imgavt.toBuffer(),
        fs.createWriteStream(
          path.join(__dirname, "public/avt-item", req.body.imgavt.filename)
        )
      );

      const oldImagePath = path.join(
        __dirname,
        `./public/avt-item/` + req.body.oldImgavt.value
      );

      console.log("oldImagePath", oldImagePath);

      // Kiểm tra tồn tại tệp cũ trước khi xóa
      if (fs.existsSync(oldImagePath)) {
        fs.unlinkSync(oldImagePath);
      }

      imgavt = req.body.imgavt.filename;
    } else {
      imgavt = req.body.oldImgavt.value;
      console.log("Sử dụng oldImgavt:", req.body.oldImgavt.value);
    }

    // Cập nhật dữ liệu trong MongoDB
    const slug = createSlug(req.body.itemname.value);
    await this.mongo.db.collection("libary").updateOne(
      { _id: new ObjectId(req.params.id) },
      {
        $set: {
          itemname: req.body.itemname.value,
          slug: slug,
          theloai: req.body.theloai.value,
          tacgia: req.body.tacgia.value,
          noidung: req.body.noidung.value,
          imgavt: imgavt,
        },
      }
    );

    rep.redirect("/admin/libary-manager");
  } catch (err) {
    console.error(err);
    rep.send({ error: "Lỗi khi cập nhật mục", message: err.message });
  }
  return rep;
});

//router(get/admin/libary-manager/delete/:id): delete a item
fastifyApp.get("/admin/libary-manager/delete/:id", async function (req, rep) {
  const result = await this.mongo.db
    .collection("libary")
    .deleteOne({ _id: new ObjectId(req.params.id) });

  rep.redirect("/admin/libary-manager");
});

//router(get/admin/list-chapters/:slug): return list chapter
fastifyApp.get(
  "/admin/list-chapters/:slug",
  { onRequest: [auth, authority("admin")] },
  async function (req, rep) {
    const chapters = await this.mongo.db
      .collection("chapters")
      .find({ item_id: req.params.slug })
      .sort({ chapter_number: 1 })
      .toArray();

    rep.render("list-chapters", { chapters, slug: req.params.slug });

    return rep;
  }
);

//router(get/admin/create-chapter/:slug): create chapter form
fastifyApp.get(
  "/admin/create-chapter/:slug",
  { onRequest: [auth, authority("admin")] },
  function handler(req, rep) {
    rep.render("create-chapter", { slug: req.params.slug });
  }
);

//router(post/admin/create-chapter/:slug): create a new chapter
fastifyApp.post("/admin/create-chapter/:slug", async function (req, rep) {
  const libary = await this.mongo.db
    .collection("libary")
    .findOne({ slug: req.params.slug });

  if (!libary) {
    return rep.status(404).send({ message: "Truyện không tìm thấy!" });
  }

  const chapterPath = path.join(
    __dirname,
    `./public/truyen/${libary.slug}/chapter-${req.body.chapter_number.value}`
  );

  try {
    if (fs.existsSync(chapterPath)) {
      fs.rmSync(chapterPath, { recursive: true });
      fs.mkdirSync(chapterPath, { recursive: true });
    } else {
      fs.mkdirSync(chapterPath, { recursive: true });
    }

    const files = await req.saveRequestFiles();
    const imageUrls = [];

    for (const file of files) {
      console.log(`Đã tải lên: ${file.filename}`);
      console.log(`Đường dẫn file tạm thời: ${file.filepath}`);

      const targetPath = path.join(chapterPath, file.filename);
      // Sao chép file vào thư mục mới
      fs.copyFileSync(file.filepath, targetPath);
      // Xóa file gốc
      fs.unlinkSync(file.filepath);

      imageUrls.push(
        `/public/truyen/${libary.slug}/chapter-${req.body.chapter_number.value}/${file.filename}`
      );
    }

    if (imageUrls.length === 0) {
      return rep.status(400).send({ message: "Không có file nào được lưu." });
    }

    await this.mongo.db.collection("chapters").insertOne({
      item_id: libary.slug,
      chapter_number: req.body.chapter_number.value,
      name_chapter: req.body.name_chapter.value,
      content: imageUrls,
    });

    rep.redirect(`/admin/list-chapters/${libary.slug}`);
  } catch (error) {
    console.error("Error during file upload:", error);
    rep.status(500).send({ message: "Đã xảy ra lỗi trong quá trình tải lên." });
  }
});

// router (get/admin/list-chapters/delete/:id): delete a chapter
fastifyApp.get("/admin/list-chapters/delete/:id", async function (req, rep) {
  try {
    const chapter = await this.mongo.db
      .collection("chapters")
      .findOne({ _id: new ObjectId(req.params.id) });

    // Tìm libary theo item_id của chapter để lấy slug
    const libary = await this.mongo.db
      .collection("libary")
      .findOne({ slug: chapter.item_id });

    const result = await this.mongo.db
      .collection("chapters")
      .deleteOne({ _id: new ObjectId(req.params.id) });

    rep.redirect(`/admin/list-chapters/${libary.slug}`);
  } catch (error) {
    rep.status(500).send({ message: "Lỗi khi xóa chapter." });
  }
});

//router(get/home): home
fastifyApp.get("/home", { onRequest: auth }, async function (req, rep) {
  const libary = await this.mongo.db.collection("libary").find({}).toArray();

  rep.render("home", { libary });

  return rep;
});

//router(get/truyen/:slug): view item
fastifyApp.get(
  "/truyen/:slug",
  { onRequest: [auth, authority("user")] },
  async function (req, rep) {
    const item = await this.mongo.db.collection("libary").findOne({
      slug: req.params.slug,
    });

    // Lấy danh sách chapters theo item_id
    const chapters = await this.mongo.db
      .collection("chapters")
      .find({
        item_id: req.params.slug,
      })
      .sort({ chapter_number: 1 })
      .toArray();

    rep.render("item", { item, chapters });

    return rep;
  }
);

//router(get/truyen/:slug/chapter-:chapter_number): view chapter
fastifyApp.get(
  "/truyen/:slug/chapter-:chapter_number",
  { onRequest: [auth, authority("user")] },
  async function (req, rep) {
    const chapter = await this.mongo.db.collection("chapters").findOne({
      chapter_number: req.params.chapter_number,
      item_id: req.params.slug,
    });

    const item = await this.mongo.db
      .collection("libary")
      .findOne({ slug: req.params.slug });

    rep.render("chapter", { chapter, item });

    return rep;
  }
);

// Run the server!
fastifyApp.listen({ port: 3000 }, (err) => {
  if (err) {
    fastifyApp.log.error(err);
    process.exit(1);
  }
});
