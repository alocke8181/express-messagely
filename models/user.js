/** User class for message.ly */
const bcrypt = require('bcrypt');

const db = require("../db");
const ExpressError = require("../expressError");

/** User of the site. */

class User {

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({username, password, first_name, last_name, phone}) {
    let hashedPW = await bcrypt.hash(password, 12); 
    const result = await db.query(`
    INSERT INTO users (
      username,
      hashedPW,
      first_name,
      last_name,
      phone,
      join_at)
      VALUES ($1, $2, $3, $4, $5, current_timestamp)
      RETURNING (username, password, first_name, last_name)`,
      [username, hashedPW, first_name, last_name, phone]);
    return result.rows[0];
  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) { 
    const result = await db.query(`
    SELECT username, password
    FROM users
    WHERE username = $1
    RETURNING username, password`,
    [username]);
    let user = result.rows[0];
    if (user == undefined){
      throw new ExpressError(`user ${username} not found`,404);
    };
    return await bcrypt.compare(password, user.password);
  };

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) { 
    const result = await db.query(`
    UPDATE users
    SET last_login_at = current_timestamp
    WHERE username = $1
    RETURNING username, last_login_at`,
    [username]);
    if (result.rows[0] == undefined){
      throw new ExpressError(`user ${username} not found`,404);
    };
  };

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() { 
    const result = await db.query(`
    SELECT * FROM users
    RETURNING username, first_name, last_name, phone`);
    return result.rows;
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) { 
    const result = await db.query(`
    SELECT * FROM users
    WHERE username = $1
    RETURNING username, first_name, last_name, phone, join_at, last_login_at`,
    [username]);
    if (result.rows[0] == undefined){
      throw new ExpressError(`user ${username} not found`,404);
    }else{
      return result.rows[0];
    };
  };

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) { 
    const result = await db.query(`
    SELECT m.id, m.to_username, m.body, m.sent_at, m.read_at,
      t.username as to_username,
      t.first_name as to_first_name,
      t.last_name as to_last_name,
      t.phone as to_phone
    FROM messages AS m
      JOIN users AS t on m.to_username = t.username
    WHERE m.from_username = $1`,
    [username]);
    if (result.rows[0] == undefined){
      throw new ExpressError(`user ${username} not found`,404);
    };
    let results = [];
    result.rows.forEach((row) => {
      results.append({
        id : m.id,
        to_user : {
          username : to_username,
          first_name : to_first_name,
          last_name : to_last_name,
          phone : to_phone
        },
        body : m.body,
        sent_at : m.sent_at,
        read_at : m.read_at
      });
    });
    return results;
  };

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) { 
    const result = await db.query(`
    SELECT m.id, m.to_username, m.body, m.sent_at, m.read_at,
      f.username as from_username,
      f.first_name as from_first_name,
      f.last_name as from_last_name,
      f.phone as from_phone
    FROM messages AS m
      JOIN users AS f on m.from_username = f.username
    WHERE m.to_username = $1`,
    [username]);
    if (result.rows[0] == undefined){
      throw new ExpressError(`user ${username} not found`,404);
    };
    let results = [];
    result.rows.forEach((row) => {
      results.append({
        id : m.id,
        from_user : {
          username : from_username,
          first_name : from_first_name,
          last_name : from_last_name,
          phone : from_phone
        },
        body : m.body,
        sent_at : m.sent_at,
        read_at : m.read_at
      });
    });
    return results;
  };
}


module.exports = User;