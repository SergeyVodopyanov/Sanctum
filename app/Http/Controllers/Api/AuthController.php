<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use Illuminate\Http\JsonResponse;
use App\Models\User;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function login(Request $request): JsonResponse
    {
        $request->validated([
            "email" => "required|email|max:255",
            "password" => "required|string|min:8|max:255"
        ]);

        $user = User::where("email", $request->email)->first();

        // if (!$user || !$user->checkPassword($request->password)) {
        // }
        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json([
                'message' => 'Электронная почта или пароль неверно укпазаны'
            ], 401);
        }

        $token = $user->createToken($user->name, 'Auth-Token')->plainTextToken;

        return response()->json([
            'message' => 'Успешная авторизация',
            'token_type' => 'Bearer',
            'token' => $token
        ], 200);
    }

    public function register(Request $request): JsonResponse
    {
        $request->validate([
            "name" => "required|string|max:255",
            "email" => "required|email|unique:users,email|max:255",
            "password" => "required|string|min:8|max:255"
        ]);

        $user = User::create([
            "name" => $request->name,
            "email" => $request->email,
            "password" => Hash::make($request->password),
        ]);

        if ($user) {
            $token = $user->createToken($user->name, 'Auth-Token')->plainTextToken;

            return response()->json([
                'message' => 'Успешная регистрация',
                'token_type' => 'Bearer',
                'token' => $token
            ], 201);
        } else {
            return response()->json([
                'message' => 'При регистрации что-то пошло не так'
            ], 500);
        }
    }
}
