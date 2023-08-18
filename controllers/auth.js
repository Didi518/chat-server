const jwt = require("jsonwebtoken");
const otpGenerator = require("otp-generator");
const crypto = require("crypto");
const { promisify } = require("util");

const User = require("../models/User");
const filterObj = require("../utils/filterObject");
const catchAsync = require("../utils/catchAsync");

const signToken = (userId) => jwt.sign({ userId }, process.env.JWT_SECRET);

exports.register = catchAsync(async (req, res, next) => {
  const { firstName, lastName, email, password } = req.body;
  const filteredBody = filterObj(
    req.body,
    "firstName",
    "lastName",
    "email",
    "password"
  );
  const existing_user = await User.findOne({ email: email });
  if (existing_user && existing_user.verified) {
    return res.status(400).json({
      status: "erreur",
      message:
        "Email déjà associée sur un compte existant. Merci de vous connecter.",
    });
  } else if (existing_user) {
    await User.findOneAndUpdate({ email: email }, filteredBody, {
      new: true,
      validateModifiedOnly: true,
    });
    req.userId = existing_user._id;
    next();
  } else {
    const new_user = await User.create(filteredBody);
    res.userId = new_user._id;
    next();
  }
});

exports.sendOTP = async (req, res, next) => {
  const { userId } = req;
  const new_otp = otpGenerator.generate(6, {
    lowerCaseAlphabets: false,
    upperCaseAlphabets: false,
    specialChars: false,
  });
  const otp_expiry_time = Date.now() + 10 * 60 * 1000;
  await User.findByIdAndUpdate(userId, { otp: new_otp, otp_expiry_time });
  // TODO mailer
  res
    .status(200)
    .json({ status: "succès", message: "Mot de passe à usage unique envoyé" });
};

exports.verifyOTP = async (req, res, next) => {
  const { email, otp } = req.body;
  const user = await User.findOne({
    email,
    otp_expiry_time: { $gt: Date.now() },
  });
  if (!user) {
    return res.status(400).json({
      status: "erreur",
      message: "Email invalide ou mot de passe à usage unique expiré",
    });
  }
  if (!(await user.correctOTP(otp, user.otp))) {
    res.status(400).json({
      status: "erreur",
      message: "Mot de passe à usage unique incorrect",
    });
  }
  user.isVerified = true;
  user.otp = undefined;
  await user.save({ new: true, validateModifiedOnly: true });
  const token = signToken(user._id);
  res
    .status(200)
    .json({ status: "succès", message: "Vérification réussie", token });
};

exports.login = async (req, res, next) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({
      status: "erreur",
      message: "L'e-mail et le mot de passe sont tous deux requis",
    });
  }
  const userDoc = await User.findOne({ email: email }).select("+password");
  if (
    !userDoc ||
    !(await userDoc.correctPassword(password, userDoc.password))
  ) {
    return res
      .status(400)
      .json({ satus: "erreur", message: "Identifiants invalides" });
  }
  const token = signToken(userDoc._id);
  res
    .status(200)
    .json({ status: "succès", message: "Connexion réussie", token });
};

exports.protect = async (req, res, next) => {
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    token = req.headers.authorization.split(" ")[1];
  } else if (req.cookies.jwt) {
    token = req.cookies.jwt;
  } else {
    res.status(400).json({
      status: "erreur",
      message: "Vous n'êtes pas en ligne. Merci de vous connecter",
    });
    return;
  }
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);
  const this_user = await User.findById(decoded.userId);
  if (!this_user) {
    res
      .status(400)
      .json({ status: "erreur", message: "Utilisateur introuvable" });
  }
  if (this_user.changedPasswordAfter(decoded.iat)) {
    res.status(400).json({
      status: "erreur",
      message:
        "Le mot de passe a été modifié récemment. Merci de vous reconnecter",
    });
  }
  req.user = this_user;
  next();
};

exports.forgotPassword = async (req, res, next) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    res
      .status(400)
      .json({ status: "error", message: "Aucun utilisateur avec cet e-mail" });
    return;
  }
  const resetToken = user.createPasswordResetToken();
  const resetURL = `htpps://chat-app.com/auth/reset-password/?code=${resetToken}`;
  try {
    // TODO => mailer
    res.status(200).json({
      status: "succès",
      message: "Lien de réinitialisation du mot de passe envoyé",
    });
  } catch (error) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });
    res.status(500).json({
      status: "erreur",
      message: "Echec de l'envoi du mail. Merci de réessayer utlitérieurement",
    });
  }
};

exports.resetPassword = async (req, res, next) => {
  const hashedToken = crypto
    .createHash("sha256")
    .update(req.params.token)
    .digest(hex);
  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() },
  });
  if (!user) {
    res
      .status(400)
      .json({ status: "erreur", message: "Token invalide ou expiré" });
    return;
  }
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  await user.save();
  // TODO => mailer
  const token = signToken(userDoc._id);
  res
    .status(200)
    .json({ status: "succès", message: "Mot de passe mis à jour", token });
};
