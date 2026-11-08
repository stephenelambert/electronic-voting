import HeaderBar from "@/components/headerbar";
import { Outlet } from "react-router-dom";

export default function Root() {
    return (
      <>
        <div id="detail">
            <HeaderBar />
            <Outlet />
        </div>
      </>
    );
  }