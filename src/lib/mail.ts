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
        from: `'nextjs-starter-kit' <${process.env.SMTP_USER}>`,
        to,
        subject: 'Redefinição de senha',
        html: `
        <p>Você solicitou uma redefinição de senha.</p>
        <p>Clique no link abaixo para criar uma nova senha:</p>
        <a href='${resetLink}'>${resetLink}</a>
        <p>Se você não solicitou isso, ignore este e-mail.</p>
        `,
    });
};

export const sendEmailVerification = async (to: string, link: string) => {
    await transporter.sendMail({
        from: `'nextjs-starter-kit' <${process.env.SMTP_USER}>`,
        to,
        subject: 'Verifique seu e-mail',
        html: `
        <h2>Confirmação por e-mail</h2>
        <p>Clique no link abaixo para confirmar seu e-mail:</p>
        <a href='${link}'>${link}</a>
        <p>Se você não solicitou isso, pode ignorar este e-mail.</p>
        `,
    });
};