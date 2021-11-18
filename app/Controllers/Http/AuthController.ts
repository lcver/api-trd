import { HttpContextContract } from '@ioc:Adonis/Core/HttpContext'
import { schema, rules } from '@ioc:Adonis/Core/Validator'
import Hash from '@ioc:Adonis/Core/Hash'
import user from 'App/Models/User'

export default class AuthController {
    async login({ request, response, auth }: HttpContextContract) {
        const newSchema = schema.create({
            email: schema.string({trim: true}, [
                rules.email(),
                rules.required()
            ]),
            password: schema.string({}, [
                rules.required(),
                rules.minLength(6)
            ])
        })

        const payload = await request.validate({ schema: newSchema})
        
        const validUser = await user.findBy("email", payload.email);
        
        if (!(await this.verivyPassword(validUser, payload.password)))
            return response.status(400).send(this.responseService(400))

        const data = await auth.attempt(payload.email, payload.password)
        // data.user = validUser?.$attributes
        console.log(data)

        return response.status(200).send(this.responseService(200, data))

    }

    async registrasi({ request, response, auth }: HttpContextContract) {
        const newSchema = schema.create({
            email: schema.string({trim: true}, [
                rules.email(),
                rules.required()
            ]),
            name: schema.string({trim: true}, [
                rules.required(),
            ]),
            password: schema.string({}, [
                rules.required(),
                rules.minLength(6)
            ])
        })

        const payload = await request.validate({ schema: newSchema })
        
        const data = await user.create(payload);
        response.status(201)

        return data
    }

    async verivyPassword(user, password) {
        if (!user)
            return false

        if (!(await Hash.verify(user.password, password)))
            return false

        return true
    }

    responseService(status, data = null) {
        switch (status) {
            case 400:
                return {
                    meta: {
                        status: 400,
                        message: "Login Failed"
                    }
                }
            case 200:
                return {
                    meta: {
                        status: 200,
                        message: "Login success"
                    },
                    data
                }
        
            default:
                break;
        }
    }
}
