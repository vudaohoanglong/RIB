import passport from 'passport';
import passportJWT from 'passport-jwt';
import { Strategy as LocalStrategy } from 'passport-local';
const { Strategy: JWTStrategy, ExtractJwt } = passportJWT;
import bcrypt from 'bcrypt';
import User from './models/User'

// Cấu hình Passport Local Strategy
passport.use(
    new LocalStrategy(
      {
        usernameField: 'email', // Tên trường chứa email
        passwordField: 'password', // Tên trường chứa mật khẩu
      },
      async (email, password, done) => {
        try {
          // Tìm người dùng với email được cung cấp
          const user = await User.findOne({ email });
  
          // Kiểm tra người dùng có tồn tại không
          if (!user) {
            return done(null, false, { message: 'Người dùng không tồn tại' });
          }
  
          // Kiểm tra mật khẩu
          const isMatch = await bcrypt.compare(password, user.password);
  
          // Kiểm tra mật khẩu có khớp không
          if (!isMatch) {
            return done(null, false, { message: 'Mật khẩu không đúng' });
          }
  
          // Xác thực thành công, trả về người dùng
          return done(null, user);
        } catch (error) {
          return done(error);
        }
      }
    )
  );
  
  // Cấu hình Passport JWT Strategy
  passport.use(
    new JWTStrategy(
      {
        jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
        secretOrKey: 'your_secret_key',
      },
      async (jwtPayload, done) => {
        try {
          // Tìm người dùng dựa trên ID trong JWT payload
          const user = await User.findById(jwtPayload.id);
  
          // Kiểm tra người dùng có tồn tại không
          if (!user) {
            return done(null, false, { message: 'Người dùng không tồn tại' });
          }
  
          // Xác thực thành công, trả về người dùng
          return done(null, user);
        } catch (error) {
          return done(error);
        }
      }
    )
  );
  
  export default passport;