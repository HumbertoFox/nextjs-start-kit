import nodemailer from 'nodemailer';

export const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT),
    secure: false,
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
    }
});

export const sendPasswordResetEmail = async (to: string, resetLink: string) => {
    await transporter.sendMail({
        from: `'nextjs-kit-starter' <${process.env.SMTP_USER}>`,
        to,
        subject: 'Password Reset',
        html: `
        <p>You have requested a password reset.</p>
        <p>Click the link below to create a new password:</p>
        <a href='${resetLink}'>${resetLink}</a>
        <p>If you did not request this, please ignore this email.</p>
        `,
    });
};

export const sendEmailVerification = async (to: string, link: string) => {
    await transporter.sendMail({
        from: `'nextjs-kit-starter' <${process.env.SMTP_USER}>`,
        to,
        subject: 'Check your email',
        html: `
        <h2>Email Confirmation</h2>
        <p>Please click the link below to confirm your email:</p>
        <a href='${link}'>${link}</a>
        <p>If you did not request this, you can ignore this email.</p>
        `,
    });
};