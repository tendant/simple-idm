import type { Component, ComponentProps, JSXElement, ParentComponent } from 'solid-js';
import { For, mergeProps, Show, splitProps } from 'solid-js';

import { cn } from '@/lib/utils';

export interface TimelineItemBulletProps {
  children?: JSXElement
  isActive?: boolean
  bulletSize: number
  lineSize: number
}

const TimelineItemBullet: Component<TimelineItemBulletProps> = (props) => {
  return (
    <div
      aria-hidden="true"
      class={cn(
        `absolute top-0 flex items-center justify-center rounded-full border bg-background`,
        props.isActive && 'border-primary',
      )}
      style={{
        'width': `${props.bulletSize}px`,
        'height': `${props.bulletSize}px`,
        'left': `${-props.bulletSize / 2 - props.lineSize / 2}px`,
        'border-width': `${props.lineSize}px`,
      }}
    >
      {props.children}
    </div>
  )
}

export type TimelinePropsItem = Omit<
  TimelineItemProps,
  'isActive' | 'isActiveBullet' | 'bulletSize' | 'lineSize'
> & {
  bulletSize?: number
}

const TimelineItemTitle: ParentComponent = (props) => {
  return (
    <div
      class="mb-1 text-base font-semibold leading-none"
    >
      {props.children}
    </div>
  )
}

const TimelineItemDescription: Component<ComponentProps<'p'>> = (props) => {
  const [local, others] = splitProps(props, ['class', 'children'])
  return (
    <p
      class={cn('text-sm text-muted-foreground', local.class)}
      {...others}
    >
      {local.children}
    </p>
  )
}

export interface TimelineProps {
  items: TimelinePropsItem[]
  activeItem: number
  bulletSize?: number
  lineSize?: number
}

const TimelineItem: Component<TimelineItemProps> = (props) => {
  const [local, others] = splitProps(props, [
    'class',
    'bullet',
    'description',
    'title',
    'isLast',
    'isActive',
    'isActiveBullet',
    'bulletSize',
    'lineSize',
  ])
  return (
    <li
      class={cn(
        'relative border-l pb-8 pl-8',
        local.isLast && 'border-l-transparent pb-0',
        local.isActive && !local.isLast && 'border-l-primary',
        local.class,
      )}
      style={{
        'border-left-width': `${local.lineSize}px`,
      }}
      {...others}
    >
      <TimelineItemBullet
        bulletSize={local.bulletSize}
        isActive={local.isActiveBullet}
        lineSize={local.lineSize}
      >
        {local.bullet}
      </TimelineItemBullet>
      <TimelineItemTitle>
        {local.title}
      </TimelineItemTitle>
      <Show
        when={local.description}
      >
        <TimelineItemDescription>
          {local.description}
        </TimelineItemDescription>
      </Show>
    </li>
  )
}

/*
  No bullet or line is active when activeItem is -1
  First bullet is active only if activeItem is 0 or more
  First line is active only if activeItem is 1 or more
*/

const Timeline: Component<TimelineProps> = (rawProps) => {
  const props = mergeProps({ bulletSize: 16, lineSize: 2 }, rawProps)

  return (
    <ul
      style={{
        'padding-left': `${props.bulletSize / 2}px`,
      }}
    >
      <For
        each={props.items}
      >
        {(item, index) => (
          <TimelineItem
            bullet={item.bullet}
            bulletSize={props.bulletSize}
            description={item.description}
            isActive={props.activeItem === -1 ? false : props.activeItem >= index() + 1}
            isActiveBullet={props.activeItem === -1 ? false : props.activeItem >= index()}
            isLast={index() === props.items.length - 1}
            lineSize={props.lineSize}
            title={item.title}
          />
        )}
      </For>
    </ul>
  )
}

export interface TimelineItemProps {
  title: JSXElement
  description?: JSXElement
  bullet?: JSXElement
  isLast?: boolean
  isActive: boolean
  isActiveBullet: boolean
  class?: string
  bulletSize: number
  lineSize: number
}

export { Timeline };
