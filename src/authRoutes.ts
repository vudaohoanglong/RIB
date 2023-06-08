import express, { Request, Response, NextFunction } from 'express';
import passport from './passport';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import User from './models/User';

const router = express.Router();

const createToken = (userId: string, email: string, role: string): string => {
  const payload = {
    userId,
    email,
    role
  };

  const secretKey = 'your_secret_key';
  const options = {
    expiresIn: '1h'
  };

  const token = jwt.sign(payload, secretKey, options);
  return token;
};


// Đăng ký
router.post('/register', async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    // Kiểm tra xem người dùng đã tồn tại hay chưa
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Người dùng đã tồn tại' });
    }

    // Tạo một người dùng mới
    const newUser = new User({ email, password });

    // Mã hóa mật khẩu trước khi lưu vào cơ sở dữ liệu
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newUser.password, salt);
    newUser.password = hashedPassword;

    // Lưu người dùng vào cơ sở dữ liệu
    await newUser.save();

    // Trả về ID của người dùng mới được tạo
    res.json({ userID: newUser._id });
  } catch (error) {
    res.status(500).json({ message: 'Đã xảy ra lỗi' });
  }
});

// Đăng nhập
router.post('/login', (req: Request, res: Response, next: NextFunction) => {
  passport.authenticate('local', { session: false }, (err, user, info) => {
    if (err || !user) {
      return res.status(401).json({ message: info.message });
    }
    console.log(user);
    // Tạo token JWT
    const token = jwt.sign({ id: user._id}, 'your_secret_key');
    // Trả về token cho client
    return res.json({ token });
  })(req, res, next);
});

// Đăng xuất
router.get('/logout', (req: Request, res: Response) => {
  // Xử lý đăng xuất tại đây (ví dụ: xóa token)
  // ...
  res.json({ message: 'Đăng xuất thành công' });
});

export default router;