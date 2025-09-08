'use client';

import { Eye, EyeClosed, LoaderCircle } from 'lucide-react';
import { startTransition, useActionState, useEffect, useRef, useState } from 'react';
import InputError from '@/components/input-error';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import AuthLayout from '@/components/layouts/auth-layout';
import { Icon } from '@/components/ui/icon';
import { createAdmin } from '@/app/api/actions/createadmin';

type RegisterForm = {
    name: string;
    email: string;
    password: string;
    password_confirmation: string;
};

export default function RegisterAdmin() {
    const emailRef = useRef<HTMLInputElement>(null);
    const [state, action, pending] = useActionState(createAdmin, undefined);
    const [showPassword, setShowPassword] = useState<boolean>(false);
    const [showPasswordConfirm, setShowPasswordConfirm] = useState<boolean>(false);
    const [data, setData] = useState<RegisterForm>({
        name: '',
        email: '',
        password: '',
        password_confirmation: '',
    });

    const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const { id, value } = e.target;
        setData({ ...data, [id]: value });
    };
    const toggleShowPassword = () => setShowPassword(prev => !prev);
    const toggleShowPasswordConfirm = () => setShowPasswordConfirm(prev => !prev);
    const submit = async (e: React.FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        const formData = new FormData(e.currentTarget);
        startTransition(() => action(formData));
    };

    useEffect(() => {
        if (state?.message) {
            setData({
                name: '',
                email: '',
                password: '',
                password_confirmation: '',
            });
        };
    }, [state]);
    return (
        <AuthLayout title="Criar uma conta Administrador" description="Insira seus dados abaixo para criar sua conta">
            <form
                onSubmit={submit}
                className="flex flex-col gap-6"
            >
                <div className="grid gap-6">
                    <div className="grid gap-2">
                        <Label htmlFor="name">Nome</Label>
                        <Input
                            id="name"
                            name="name"
                            type="text"
                            required
                            autoFocus
                            tabIndex={1}
                            autoComplete="name"
                            value={data.name}
                            onChange={handleChange}
                            disabled={pending}
                            placeholder="Nome completo"
                        />
                        {state?.errors?.name && <InputError message={state.errors.name} />}
                    </div>

                    <div className="grid gap-2">
                        <Label htmlFor="email">Endereço de email</Label>
                        <Input
                            id="email"
                            name="email"
                            type="email"
                            ref={emailRef}
                            required
                            tabIndex={2}
                            autoComplete="email"
                            value={data.email}
                            onChange={handleChange}
                            disabled={pending}
                            placeholder="email@exemplo.com"
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
                                required
                                tabIndex={3}
                                autoComplete="new-password"
                                value={data.password}
                                onChange={handleChange}
                                disabled={pending}
                                placeholder="Senha"
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
                                name="password_confirmation"
                                type={showPasswordConfirm ? "text" : "password"}
                                required
                                tabIndex={4}
                                autoComplete="new-password"
                                value={data.password_confirmation}
                                onChange={handleChange}
                                disabled={pending}
                                placeholder="Confirme sua senha"
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

                    <Button
                        type="submit"
                        tabIndex={6}
                        disabled={pending}
                        aria-busy={pending}
                        className="mt-2 w-full"
                    >
                        {pending && <LoaderCircle className="h-4 w-4 animate-spin" />}
                        Criar uma conta
                    </Button>
                </div>
            </form>

            {state?.warning && <div className="mb-4 text-center text-sm font-medium text-orange-400">{state.warning}</div>}
        </AuthLayout>
    );
}
