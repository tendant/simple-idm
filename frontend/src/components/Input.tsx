import { cn } from "@/lib/utils";
import { JSX, splitProps } from "solid-js";

export type IInputProps = JSX.InputHTMLAttributes<HTMLInputElement>


export const Input = (props:IInputProps)=>{
  const [local, others] = splitProps(props, ["class"])
  return <input class={cn("block w-full appearance-none rounded-lg border px-3 py-2 placeholder-gray-8 shadow-sm focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500", local.class)} {...others} />
}
