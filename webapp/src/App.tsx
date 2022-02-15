import React from "react";
import "./App.css";
import {
    BrowserRouter as Router,
    Route,
    Routes,
} from "react-router-dom";
import { StarknetProvider } from "./providers/StarknetProvider";

import Header from "./components/Header/Header"
import Footer from "./components/Footer/Footer"
import HomePage from "./pages/Home/HomePage"
import MintPage from "./pages/Mint/MintPage"
import ViewBadgePage from "./pages/Badges/ViewBadgePage"

export default function App() {
    return (
      <StarknetProvider>
        <Router>
          <Header />
          <Routes>
            <Route path="/" element={<HomePage/>}/>
            <Route path="/mint" element={<MintPage/>}/>
            <Route path="/view_badges" element={<ViewBadgePage/>}/>
          </Routes>
          <Footer />
        </Router>
      </StarknetProvider>
    )
}
