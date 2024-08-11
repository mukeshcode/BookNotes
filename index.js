import express from "express";
import pg from "pg";
import { dirname } from "path";
import { fileURLToPath } from "url";
import path from "path";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import bcrypt from "bcrypt";
import env from "dotenv";

const app = express();
const PORT = process.env.PORT || 3000;
const saltRounds = 10;
const __dirname = dirname(fileURLToPath(import.meta.url));

let booksData = [];
env.config();

app.use(express.static(path.join(__dirname, 'public')))
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24
  }
}))
app.use(passport.initialize());
app.use(passport.session());

// Will automatically run only once
const db = new pg.Client({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  database: process.env.DB_NAME,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT
});

db.connect();

app.post("/login", passport.authenticate("local", {
  successRedirect: "/",
  failureRedirect: "/login",
}));

app.get("/login", (req, res) => {
  res.render("login.ejs");
})

app.post("/logout", (req, res, next) => {
  req.logout(function (err) {
    if (err) return next(err);
    res.redirect("/");
  })
})

app.get("/create", (req, res) => {
  res.render("create.ejs");
});

app.post("/create", async (req, res) => {
  try {
    const username = req.body.username;
    const password = req.body.password;

    if (username == "" || password == "") {
      res.render("create.ejs", { message: "Missing username or password!" });
    } else {
      const result1 = await db.query("SELECT * FROM users WHERE username=$1", [username]);
      if (result1.rows.length == 0) {
        bcrypt.hash(password, saltRounds, async (error, hash) => {
          if (error) {
            console.log("Error in hashing password : " + err);
            res.render("create.ejs", { message: "Error in hashing password ! " })
          } else {
            const result = await db.query("INSERT INTO users(username, password) VALUES($1,$2) RETURNING *", [username, hash]);
            const user = result.rows[0];
            req.login(user, (err) => {
              if (err) {
                console.log(err);
              }
              res.redirect("/");
            })
          }
        })
      } else {
        res.render("create.ejs", { message: "Username already used !" });
      }
    }

  } catch (err) {
    console.log(err)
    res.render("create.ejs", { message: "Error in creating account. Try again!" });
  }
})


app.get("/", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      await fetchLatestBookInfo(req.user.id);
      res.render("index.ejs", {
        booksData: booksData,
        username: req.user.username
      });
    } catch (err) {
      res.render("index.ejs", {
        booksData: booksData,
        username: req.user.username
      });
    }
  } else {
    res.render("login.ejs");
  }
});



app.get("/book/:id", async (req, res) => {
  const id = req.params['id'];

  const book = booksData.find(book => String(book.id) === String(id));
  // console.log(book);
  if (!book) {
    res.render("error.ejs", { error: "Book doesn't exist! " });
  }
  else {
    db.query("SELECT * from note WHERE book_id = $1", [id], (err, results) => {
      if (err) {
        console.log("Error in getting notes", err);
        res.render("error.ejs", { error: "Error in getting notes" });
      } else {
        let notes = results.rows;
        res.render("book.ejs", { book: book, notes: notes });
      }
    });
  }

})

app.get("/addBookForm", (req, res) => {
  res.render("addBookForm.ejs");
});

app.post("/addBook", async (req, res) => {
  console.log(req.body);
  let name = req.body['name'], date_read = req.body['date_read'], isbn = req.body['isbn'], rating = Number(req.body['rating']), author = req.body['author'], link = req.body['link'], complete = req.body['complete'];
  db.query("INSERT INTO book(name, date_read, isbn, rating, author, link, complete, user_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)", [name, date_read, isbn, rating, author, link, complete, req.user.id], (err, result) => {
    if (err) {
      console.log('Error in adding new book', err);
      res.render("error.ejs", { error: "Fill the fields correctly!" });
    } else {
      res.redirect("/");
    }
  });
})

app.get("/updateBookForm/:id", (req, res) => {
  const id = req.params['id'];
  const currBook = booksData.find(book => book.id == id);
  if (!currBook) {
    console.log("Requested book not found!");
    res.render("error.ejs", { error: "Requested book not found!" })
  }
  console.log(currBook);
  res.render("updateBookForm.ejs", { book: currBook });
});

app.post("/updateBook/:id", async (req, res) => {
  const id = req.params['id'];
  const name = req.body['name'], date_read = req.body['date_read'], isbn = req.body['isbn'], rating = Number(req.body['rating']), author = req.body['author'], link = req.body['link'], complete = req.body['complete'] === 'true' ? true : false;
  db.query("UPDATE book SET name = $1, date_read = $2, isbn = $3, rating = $4, author = $5, link = $6, complete = $7 WHERE id = $8", [name, date_read, isbn, rating, author, link, complete, id], (err, result) => {
    if (err) {
      console.log("Error in updating values", err);
      res.render("error.ejs", { error: "Error in updating values! Please fill the data correctly!" });
    } res.redirect("/");
  });
})

app.post("/deleteBook", async (req, res) => {
  const bookId = req.body.bookId;

  db.query('DELETE FROM book where id = $1', [bookId], (err, result) => {
    if (err) {
      console.log(err);
      res.status(404).send("NOT OK");
    } else {
      res.status(200).send("Absolutely fine");
    }
  });

})

app.post("/book/:id/addNote", (req, res) => {
  const note_text = req.body['note_text'];
  const book_id = req.params.id;
  db.query("INSERT INTO note(book_id, note_text) values ($1, $2)", [book_id, note_text], (err, result) => {
    if (err) {
      console.error("Error in adding note", err)
      res.render("error.ejs", { error: "Error in adding note" })
    } else {
      res.redirect(`/book/${book_id}`);
    }
  })

})




app.post("/updateNote", async (req, res) => {
  const id = req.body['id'], note_text = req.body['note_text'];

  try {
    const result = await db.query("UPDATE note SET note_text = $1 WHERE id = $2", [note_text, id]); res.status(200).send("OK");
  } catch (error) {
    console.log("Error in updating note");
    res.status(404).send("Some problem");
  }
})

app.get("/deleteNote", (req, res) => {
  try {
    const result = db.query("DELETE FROM note where id = $1", [req.query['note_id']]);
    res.sendStatus(200);
  } catch (err) {
    console.log(err);
    res.sendStatus(500);
  }
})

// Helper functions
async function fetchLatestBookInfo(id) {
  try {
    const res = await db.query("SELECT id, name, TO_CHAR(date_read, 'YYYY-MM-DD') AS date_read, isbn, rating, author, link, complete from book where user_id=$1 ORDER BY id", [id]);

    if (res.rows.length == 0) {
      console.log("Error in fetching books");
    } else {
      booksData = res.rows;
    }
  } catch (err) {
    booksData = null;
    console.log(err)
  }  // }
}


// Why to write this at the end?
passport.use(new Strategy(async function verify(username, password, cb) {
  if (username == "" || password == "")
    return cb("Blank username or password");
  try {
    const result = await db.query("SELECT * FROM users WHERE username=$1", [username]);
    if (result.rows.length > 0) {
      const storedPassword = result.rows[0].password;
      const compareResult = await bcrypt.compare(password, storedPassword);
      if (compareResult) {
        const user = result.rows[0];
        return cb(null, user);
      } else {
        return cb(null, false, { message: "Incorrect password" });
      }
    } else {
      console.log("In verify function : wrong username or password");
      return cb(null, false, { message: "wrong username or password" })
    }
  } catch (err) {
    return cb(err);
  }
}));

passport.serializeUser((user, cb) => {
  cb(null, user.id);
});
passport.deserializeUser(async (id, cb) => {
  try {
    const res = await db.query("SELECT id, username FROM users where id=$1 ", [id]);
    if (res.rows.length == 0)
      return cb(null, false);
    else {
      const user = res.rows[0];
      return cb(null, user);
    }
  } catch (err) {
    return cb(err);
  }
});

app.listen(PORT, () => {
  console.log(`Server up and running on port ${PORT}`);
});