"use client"
import { Routes, Route } from "react-router-dom"
import { useAuth } from "./contexts/AuthContext"
import React from 'react';

// Layouts
import MainLayout from "./layouts/MainLayout"
import AdminLayout from "./layouts/AdminLayout"

// Public Pages
import HomePage from "./pages/HomePage"
import LoginPage from "./pages/LoginPage"
import RegisterPage from "./pages/RegisterPage"
import ForgotPasswordPage from "./pages/ForgotPasswordPage"
import ResetPasswordPage from "./pages/ResetPasswordPage"
import CarsPage from "./pages/CarsPage"
import CarDetailsPage from "./pages/CarDetailsPage"
import Terms from "./pages/TermsPage"
import Privacy from "./pages/PrivacyPage"

// Protected Pages
import ProfilePage from "./pages/ProfilePage"
import BookingPage from "./pages/BookingPage"
import MyBookingsPage from "./pages/MyBookingsPage"
import BookingDetailsPage from "./pages/BookingDetailsPage"
import PaymentPage from "./pages/PaymentPage"

// Admin Pages
import AdminDashboardPage from "./pages/admin/DashboardPage"
import AdminCarsPage from "./pages/admin/CarsPage"
import AdminCarFormPage from "./pages/admin/CarFormPage"
import AdminBookingsPage from "./pages/admin/BookingsPage"
import AdminUsersPage from "./pages/admin/UsersPage"
import AdminPaymentsPage from "./pages/admin/PaymentsPage"

// Guards
import ProtectedRoute from "./components/guards/ProtectedRoute"
import AdminRoute from "./components/guards/AdminRoute"
import PublicRoute from "./components/guards/PublicRoute"

function App() {
  const { loading } = useAuth()

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-primary-600"></div>
      </div>
    )
  }

  return (
    <Routes>
      {/* Public Routes */}
      <Route path="/" element={<MainLayout />}>
        <Route index element={<HomePage />} />
        <Route path="cars" element={<CarsPage />} />
        <Route path="cars/:id" element={<CarDetailsPage />} />
        <Route path="/terms" element={<Terms/> } ></Route>
         <Route path="/privacy" element={<Privacy/> } ></Route>

        <Route element={<PublicRoute />}>
          <Route path="login" element={<LoginPage />} />
          <Route path="register" element={<RegisterPage />} />
          <Route path="forgot-password" element={<ForgotPasswordPage />} />
          <Route path="reset-password" element={<ResetPasswordPage />} />
        </Route>

        {/* Protected Routes */}
        <Route element={<ProtectedRoute />}>
          <Route path="profile" element={<ProfilePage />} />
          <Route path="booking/:carId" element={<BookingPage />} />
          <Route path="my-bookings" element={<MyBookingsPage />} />
          <Route path="booking-details/:id" element={<BookingDetailsPage />} />
          <Route path="payment/:bookingId" element={<PaymentPage />} />
        </Route>
      </Route>

      {/* Admin Routes */}
      <Route element={<AdminRoute />}>
        <Route path="/admin" element={<AdminLayout />}>
          <Route index element={<AdminDashboardPage />} />
          <Route path="cars" element={<AdminCarsPage />} />
          <Route path="cars/add" element={<AdminCarFormPage />} />
          <Route path="cars/edit/:id" element={<AdminCarFormPage />} />
          <Route path="bookings" element={<AdminBookingsPage />} />
          <Route path="users" element={<AdminUsersPage />} />
          <Route path="payments" element={<AdminPaymentsPage />} />
        </Route>
      </Route>
    </Routes>
  )
}

export default App
