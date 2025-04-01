import type { Component } from 'solid-js';

export const Spinner: Component<{ size?: 'sm' | 'md' | 'lg' }> = (props) => {
  const sizeClass = {
    sm: 'w-4 h-4',
    md: 'w-6 h-6',
    lg: 'w-8 h-8',
  }[props.size || 'md'];

  return (
    <div
      class="flex items-center justify-center"
    >
      <div
        class={`animate-spin rounded-full border-2 border-gray-300 border-t-primary ${sizeClass}`}
      />
    </div>
  );
};

export default Spinner;
