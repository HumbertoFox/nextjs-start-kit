'use client';

import { Eye, EyeClosed, LoaderCircle } from 'lucide-react';
import { startTransition, useActionState, useEffect, useState } from 'react';
import InputError from '@/components/input-error';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import AuthLayout from '@/components/layouts/auth-layout';
import { Icon } from '@/components/ui/icon';
import { resetPassword } from '@/app/api/auth/resetpassword';
import { useSearchParams } from 'next/navigation';

type ResetPasswordForm = {
    token: string;
    email: string;
    password: string;
    password_confirmation: string;
};

export default function ResetPasswordClient() {
    const searchParams = useSearchParams();
    const [state, action, pending] = useActionState(resetPassword, undefined);
    const [showPassword, setShowPassword] = useState<boolean>(false);
    const [showPasswordConfirm, setShowPasswordConfirm] = useState<boolean>(false);
    const [data, setData] = useState<Required<ResetPasswordForm>>({
        token: searchParams.get('token') ?? '',
        email: searchParams.get('email') ?? '',
        password: '',
        password_confirmation: ''
    });

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const { id, value } = e.target;
        setData({ ...data, [id]: value });
    };
    const toggleShowPassword = () => setShowPassword(!showPassword);
    const toggleShowPasswordConfirm = () => setShowPasswordConfirm(!showPasswordConfirm);
    const submit = async (e: React.FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        const formData = new FormData(e.currentTarget);
        startTransition(() => action(formData));
    };
    useEffect(() => {
        if (state?.message) {
            setData({
                ...data,
                password: '',
                password_confirmation: ''
            });
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [state]);
    return (
        <AuthLayout
            title="Redefinir senha"
            description="Por favor, digite sua nova senha abaixo."
        >
            <form onSubmit={submit}>
                <div className="grid gap-6">
                    <div className="grid gap-2">
                        <Label htmlFor="email">E-mail</Label>
                        <Input
                            id="email"
                            type="email"
                            name="email"
                            tabIndex={1}
                            autoComplete="email"
                            value={data.email}
                            readOnly
                            onChange={handleChange}
                            required
                            className="block w-full"
                        />
                        {state?.errors?.email && <InputError message={state.errors.email} />}
                    </div>

                    <div className="grid gap-2">
                        <Label htmlFor="password">Senha</Label>
                        <div className="relative">
                            <Input
                                id="password"
                                name="password"
                                type={showPassword ? "text" : "password"}
                                tabIndex={2}
                                value={data.password}
                                className="block w-full"
                                autoFocus
                                onChange={handleChange}
                                placeholder="Senha"
                                required
                            />
                            <button
                                type="button"
                                className='absolute right-2 top-[6px] opacity-30 hover:opacity-100 duration-300 cursor-pointer'
                                onClick={toggleShowPassword}
                            >
                                {showPassword ? <Icon iconNode={Eye} /> : <Icon iconNode={EyeClosed} />}
                            </button>
                        </div>
                        {state?.errors?.password && <InputError message={state.errors.password} />}
                    </div>

                    <div className="grid gap-2">
                        <Label htmlFor="password_confirmation">Confirme sua senha</Label>
                        <div className="relative">
                            <Input
                                id="password_confirmation"
                                type={showPasswordConfirm ? "text" : "password"}
                                name="password_confirmation"
                                tabIndex={3}
                                autoComplete="new-password"
                                value={data.password_confirmation}
                                onChange={handleChange}
                                placeholder="Confirme sua senha"
                                required
                                className="block w-full"
                            />
                            <button
                                type="button"
                                className='absolute right-2 top-[6px] opacity-30 hover:opacity-100 duration-300 cursor-pointer'
                                onClick={toggleShowPasswordConfirm}
                            >
                                {showPasswordConfirm ? <Icon iconNode={Eye} /> : <Icon iconNode={EyeClosed} />}
                            </button>
                        </div>
                        {state?.errors?.password_confirmation && <InputError message={state.errors.password_confirmation} />}
                    </div>

                    <input type="hidden" name="token" value={data.token} />

                    <Button
                        type="submit"
                        disabled={pending}
                        className="mt-4 w-full"
                    >
                        {pending && <LoaderCircle className="h-4 w-4 animate-spin" />}
                        Redefinir senha
                    </Button>
                </div>
            </form>

            {state?.message && <div className="mb-4 text-center text-sm font-medium text-blue-600">{state.message}</div>}
            {state?.warning && <div className="mb-4 text-center text-sm font-medium text-red-600">{state.warning}</div>}
        </AuthLayout>
    );
}
