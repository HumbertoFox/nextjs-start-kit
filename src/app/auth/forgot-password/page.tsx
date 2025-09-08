'use client';

import { LoaderCircle } from 'lucide-react';
import { ChangeEvent, FormEvent, startTransition, useActionState, useState } from 'react';
import InputError from '@/components/input-error';
import TextLink from '@/components/text-link';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import AuthLayout from '@/components/layouts/auth-layout';
import { forgotPassword } from '@/app/api/auth/forgotpassword';

export default function ForgotPassword() {
    const [state, action, pending] = useActionState(forgotPassword, undefined);
    const [data, setData] = useState<Required<{ email: string }>>({ email: '' });

    const handleChange = (e: ChangeEvent<HTMLInputElement>) => {
        const { id, value } = e.target;
        setData({ ...data, [id]: value });
    };
    const submit = async (e: FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        const formData = new FormData(e.currentTarget);
        startTransition(() => action(formData));
    };
    return (
        <AuthLayout
            title="Esqueceu sua senha?"
            description="Digite seu e-mail para receber um link para redefinir sua senha"
        >
            {state?.message && <div className="mb-4 text-center text-sm font-medium text-blue-600">{state.message}</div>}

            <div className="space-y-6">
                <form onSubmit={submit}>
                    <div className="grid gap-2">
                        <Label htmlFor="email">Endereço de email</Label>
                        <Input
                            id="email"
                            type="email"
                            name="email"
                            autoComplete="off"
                            value={data.email}
                            autoFocus
                            onChange={handleChange}
                            placeholder="email@exemplo.com"
                            required
                        />
                        {state?.errors?.email && <InputError message={state.errors.email} />}
                    </div>

                    <div className="my-6 flex items-center justify-start">
                        <Button
                            disabled={pending}
                            className="w-full"
                        >
                            {pending && <LoaderCircle className="h-4 w-4 animate-spin" />}
                            Link para redefinição de senha de e-mail
                        </Button>
                    </div>
                </form>

                <div className="text-muted-foreground space-x-1 text-center text-sm">
                    <span>Ou, volte para</span>
                    <TextLink href="/login">Conecte-se</TextLink>
                </div>
            </div>
        </AuthLayout>
    );
}
