import { Schema, model, Document } from 'mongoose';

interface IUser extends Document {
  email: string;
  password: string;
}

const userSchema = new Schema<IUser>({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const MyUser = model<IUser>('User', userSchema);

export default MyUser;