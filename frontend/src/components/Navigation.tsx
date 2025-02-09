import { Component } from 'solid-js';
import { A } from '@solidjs/router';
import { logout } from '@/lib/auth';
import { Button } from '@/components/ui/button';

const Navigation: Component = () => {
  return (
    <nav class="bg-gray-2 shadow">
      <div class="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div class="flex h-16 justify-between">
          <div class="flex">
            <div class="flex flex-shrink-0 items-center">
              <span class="text-xl font-bold text-gray-12">Simple IDM</span>
            </div>
            <div class="ml-6 flex space-x-8">
              <A
                href="/users"
                class="inline-flex items-center border-b-2 border-transparent px-1 pt-1 text-sm font-medium text-gray-11 hover:border-gray-7 hover:text-gray-12"
                activeClass="border-blue-500 text-gray-12"
              >
                Users
              </A>
              <A
                href="/roles"
                class="inline-flex items-center border-b-2 border-transparent px-1 pt-1 text-sm font-medium text-gray-11 hover:border-gray-7 hover:text-gray-12"
                activeClass="border-blue-500 text-gray-12"
              >
                Roles
              </A>
            </div>
          </div>
          <div class="flex items-center">
            <Button
              variant="ghost"
              onClick={async () => {
                try {
                  await logout();
                } catch (error) {
                  console.error('Logout failed:', error);
                }
              }}
            >
              Logout
            </Button>
          </div>
        </div>
      </div>
    </nav>
  );
};

export default Navigation;
