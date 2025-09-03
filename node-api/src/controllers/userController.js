import { StatusCodes } from 'http-status-codes'
import { pickUser } from '~/utils/formatters'
import { authenticator } from 'otplib'
import QRCode from 'qrcode'
// LƯU Ý: Trong ví dụ về xác thực 2 lớp Two-Factor Authentication (2FA) này thì chúng ta sẽ sử dụng nedb-promises để lưu và truy cập dữ liệu từ một file JSON. Coi như file JSON này là Database của dự án.
const Datastore = require('nedb-promises')
const UserDB = Datastore.create('src/database/users.json')
const TwoFASecretKeyDB = Datastore.create('src/database/2fa_secret_keys.json')
const UserSessionsDB = Datastore.create('src/database/user_sessions.json')
const SERVICE_NAME = '2FA - Linh'
const login = async (req, res) => {
  try {
    const user = await UserDB.findOne({ email: req.body.email })
    // Không tồn tại user
    if (!user) {
      res.status(StatusCodes.NOT_FOUND).json({ message: 'User not found!' })
      return
    }
    // Kiểm tra mật khẩu "đơn giản". LƯU Ý: Thực tế phải dùng bcryptjs để hash mật khẩu, đảm bảo mật khẩu được bảo mật. Ở đây chúng ta làm nhanh gọn theo kiểu so sánh string để tập trung vào nội dung chính là 2FA.
    // Muốn học về bcryptjs cũng như toàn diện kiến thức đầy đủ về việc làm một trang web Nâng Cao thì các bạn có thể theo dõi khóa MERN Stack Advanced này. (Public lên phần hội viên của kênh vào tháng 12/2024)
    // https://www.youtube.com/playlist?list=PLP6tw4Zpj-RJbPQfTZ0eCAXH_mHQiuf2G
    if (user.password !== req.body.password) {
      res
        .status(StatusCodes.NOT_ACCEPTABLE)
        .json({ message: 'Wrong password!' })
      return
    }
    let resUser = pickUser(user)

    // Khi dang nhap thanh cong thi se tao moi mot phien dang nhap tam thoi bang user_sessions voi (is_2fa_verified: false),
    //cho user do voi dinh danh trinh duyet hien tai

    // Tim phien dang nhap hien tai cua user voi device_id
    let currentUserSession = await UserSessionsDB.findOne({
      user_id: user._id,
      device_id: req.headers['user-agent'],
    })

    // Neu user chua co phien thi tao moi phien dang nhap tam thoi cho user voi device_id
    if (!currentUserSession) {
      currentUserSession = await UserSessionsDB.insert({
        user_id: user._id,
        device_id: req.headers['user-agent'],
        is_2fa_verified: false,
        last_login: Date.now()
      })
    }

    resUser['is_2fa_verified'] = currentUserSession.is_2fa_verified
    resUser['last_login'] = currentUserSession.last_login
    res.status(StatusCodes.OK).json(resUser)
  } catch (error) {
    res
      .status(StatusCodes.INTERNAL_SERVER_ERROR)
      .json({ message: error.message })
  }
}

const getUser = async (req, res) => {
  try {
    const user = await UserDB.findOne({ _id: req.params.id })
    if (!user) {
      res.status(StatusCodes.NOT_FOUND).json({ message: 'User not found!' })
      return
    }

    const resUser = pickUser(user)
    // neu user bat 2fa thi tim kiem trong session hien tai cua user theo userId va deviceId
    // if (user.require_2fa) {
    const currentUserSession = await UserSessionsDB.findOne({
      user_id: user._id,
      device_id: req.headers['user-agent'],
    })
    resUser['is_2fa_verified'] = currentUserSession
      ? currentUserSession.is_2fa_verified
      : null
    resUser['last_login'] = currentUserSession
      ? currentUserSession.last_login
      : null

    res.status(StatusCodes.OK).json(resUser)
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error)
  }
}

const logout = async (req, res) => {
  try {
    const user = await UserDB.findOne({ _id: req.params.id })
    if (!user) {
      res.status(StatusCodes.NOT_FOUND).json({ message: 'User not found!' })
      return
    }

    // Xóa phiên của user trong Database > user_sessions tại đây khi đăng xuất
    await UserSessionsDB.deleteMany({
      user_id: user._id,
      device_id: req.headers['user-agent'],
    })
    UserSessionsDB.compactDatafileAsync()

    res.status(StatusCodes.OK).json({ loggedOut: true })
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error)
  }
}

const get2FA_QCode = async (req, res) => {
  try {
    const user = await UserDB.findOne({ _id: req.params.id })
    if (!user) {
      res.status(StatusCodes.NOT_FOUND).json({ message: 'User not found!' })
      return
    }

    // Biến lưu trữ 2fa secretkey của user
    let twoFactorSecretKeyValue = null

    // Lay 2fa secretkey cua user tu bang 2fa_secret_keys
    const twoFASecretKey = await TwoFASecretKeyDB.findOne({ user_id: user._id })
    if (!twoFASecretKey) {
      const newTwoFactorSecretKey = await TwoFASecretKeyDB.insert({
        user_id: user._id,
        value: authenticator.generateSecret(), // Tạo mới 2fa secretkey
      })
      twoFactorSecretKeyValue = newTwoFactorSecretKey.value
    } else {
      twoFactorSecretKeyValue = twoFASecretKey.value
    }

    // Tạo OTP token để tạo QR code
    const otpAuthToken = authenticator.keyuri(
      user.username,
      SERVICE_NAME,
      twoFactorSecretKeyValue
    )

    // Tạo một ảnh QR Code từ otpAuthToken để gửi về cho Client
    const qrCodeImageUrl = await QRCode.toDataURL(otpAuthToken)

    res.status(StatusCodes.OK).json({ qrcode: qrCodeImageUrl })
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error)
  }
}

const setup2FA = async (req, res) => {
  try {
    const user = await UserDB.findOne({ _id: req.params.id })
    if (!user) {
      res.status(StatusCodes.NOT_FOUND).json({ message: 'User not found!' })
      return
    }

    // Lay secret key cua user tu bang 2fa_secret_keys
    const twoFASecretKey = await TwoFASecretKeyDB.findOne({ user_id: user._id })
    if (!twoFASecretKey) {
      res
        .status(StatusCodes.NOT_FOUND)
        .json({ message: '2FA Secret Key not found!' })
      return
    }

    // kiem tra otp tu client gui lenh
    const clientOtpToken = req.body.otpToken
    if (!clientOtpToken) {
      res
        .status(StatusCodes.NOT_FOUND)
        .json({ message: 'OTP token is required!' })
      return
    }
    const isValid = authenticator.verify({
      token: clientOtpToken,
      secret: twoFASecretKey.value,
    })
    if (!isValid) {
      res
        .status(StatusCodes.NOT_ACCEPTABLE)
        .json({ message: 'Invalid OTP token!' })
      return
    }

    // Neu otp token hop le thi nghia la xac thuc 2fa thanh cong, tiep theo se cap nhat lai thong tin require_2fa trong user db
    const updatedUser = await UserDB.update(
      { _id: user._id },
      { $set: { require_2fa: true } },
      { returnUpdatedDocs: true }
    )

    UserDB.compactDatafileAsync()

    // Vì user lúc này mới bật 2fa nên chúng ta sẽ tạo mới một phiên đăng nhập hợp lệ cho user với định danh trình duyệt hiện tại

    const updatedUserSession = await UserSessionsDB.update(
      { user_id: user._id, device_id: req.headers['user-agent'] },
      { $set: { is_2fa_verified: true } },
      { returnUpdatedDocs: true }
    )

    UserSessionsDB.compactDatafileAsync()
    // Tra ve du lieu cho phia frontend
    res.status(StatusCodes.OK).json({
      ...pickUser(updatedUser),
      is_2fa_verified: updatedUserSession.is_2fa_verified,
      last_login: updatedUserSession.last_login,
    })
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error)
  }
}

const verify2FA = async (req, res) => {
  try {
    const user = await UserDB.findOne({ _id: req.params.id })
    if (!user) {
      res.status(StatusCodes.NOT_FOUND).json({ message: 'User not found!' })
      return
    }

    // Lay secret key cua user tu bang 2fa_secret_keys
    const twoFASecretKey = await TwoFASecretKeyDB.findOne({ user_id: user._id })
    if (!twoFASecretKey) {
      res
        .status(StatusCodes.NOT_FOUND)
        .json({ message: '2FA Secret Key not found!' })
      return
    }

    // neu user da co secret key thi kiem tra otp tu client gui lenh
    const clientOtpToken = req.body.otpToken
    if (!clientOtpToken) {
      res
        .status(StatusCodes.NOT_FOUND)
        .json({ message: 'OTP token is required!' })
      return
    }

    const isValid = authenticator.verify({
      token: clientOtpToken,
      secret: twoFASecretKey.value,
    })
    if (!isValid) {
      res
        .status(StatusCodes.NOT_ACCEPTABLE)
        .json({ message: 'Invalid OTP token!' })
      return
    }

    // Neu OTP token hop le thi buoc xac thuc 2FA thanh cong, Cap nhat lai phien dang nhap hop le cho user
    const updatedUserSession = await UserSessionsDB.update(
      { user_id: user._id, device_id: req.headers['user-agent'] },
      { $set: { is_2fa_verified: true } },
      { returnUpdatedDocs: true }
    )

    UserSessionsDB.compactDatafileAsync()

    res.status(StatusCodes.OK).json({
      ...pickUser(user),
      is_2fa_verified: updatedUserSession.is_2fa_verified,
      last_login: updatedUserSession.last_login,
    })
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error)
  }
}

export const userController = {
  login,
  getUser,
  logout,
  get2FA_QCode,
  setup2FA,
  verify2FA,
}
